/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nbsetupkey

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"

	auth "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
)

func TestObserve(t *testing.T) {
	type fields struct {
		authManager *auth.AuthManager
	}

	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		o   managed.ExternalObservation
		err error
	}

	cases := map[string]struct {
		reason string
		fields fields
		args   args
		want   want
	}{
		// TODO: Add test cases.
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{authManager: tc.fields.authManager}
			got, err := e.Observe(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, got); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want, +got:\n%s\n", tc.reason, diff)
			}
		})
	}
}

// fakeAuthClient satisfies the authClient interface and returns a real netbird
// client pointed at an httptest server.
type fakeAuthClient struct {
	client *netbird.Client
}

// GetClient returns the stubbed netbird REST client.
func (f *fakeAuthClient) GetClient(_ context.Context) (*netbird.Client, error) {
	return f.client, nil
}

// ForceRefresh is a no-op in the fake.
func (f *fakeAuthClient) ForceRefresh(_ context.Context) error { return nil }

// newFakeAuth returns a fakeAuthClient backed by an httptest server.
func newFakeAuth(t *testing.T, h http.HandlerFunc) (*fakeAuthClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	c := netbird.NewWithOptions(
		netbird.WithManagementURL(srv.URL),
		netbird.WithPAT("test-token"),
	)
	return &fakeAuthClient{client: c}, srv
}

// TestObserveAdoption covers adoption by name, which prevents a Create whose
// external-name persist failed from minting a duplicate setup key.
func TestObserveAdoption(t *testing.T) {
	t.Run("EmptyLookupAdoptsValidKeyByName", func(t *testing.T) {
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/setup-keys" && r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"sk-1","name":"bootstrap-key","revoked":false,"expires":"2099-01-01T00:00:00Z","last_used":"2026-01-01T00:00:00Z","state":"valid","type":"reusable","auto_groups":[]}]`))
				return
			}
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbSetupKey{ObjectMeta: metav1.ObjectMeta{Name: "tenant-bootstrap"}}
		cr.Spec.ForProvider.Name = "bootstrap-key"

		obs, err := e.Observe(context.Background(), cr)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !obs.ResourceExists {
			t.Fatalf("expected adoption (ResourceExists=true), got %+v", obs)
		}
		if !obs.ResourceUpToDate {
			t.Errorf("expected up-to-date on adoption (Update would rotate the key), got %+v", obs)
		}
		if cr.Status.AtProvider.Id != "sk-1" {
			t.Errorf("expected status.atProvider.id 'sk-1', got %q", cr.Status.AtProvider.Id)
		}
	})

	t.Run("RevokedAndExpiredKeysAreNotAdopted", func(t *testing.T) {
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/setup-keys" && r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[
					{"id":"sk-revoked","name":"bootstrap-key","revoked":true,"expires":"2099-01-01T00:00:00Z","last_used":"2026-01-01T00:00:00Z","state":"revoked","type":"reusable","auto_groups":[]},
					{"id":"sk-expired","name":"bootstrap-key","revoked":false,"expires":"2020-01-01T00:00:00Z","last_used":"2026-01-01T00:00:00Z","state":"expired","type":"reusable","auto_groups":[]}
				]`))
				return
			}
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbSetupKey{ObjectMeta: metav1.ObjectMeta{Name: "tenant-bootstrap"}}
		cr.Spec.ForProvider.Name = "bootstrap-key"

		obs, err := e.Observe(context.Background(), cr)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if obs.ResourceExists {
			t.Errorf("expected no adoption of revoked/expired keys, got %+v", obs)
		}
	})
}

// keyServer fakes the netbird setup-key API for one key and records the
// mutating calls made against it.
type keyServer struct {
	key     string
	puts    []api.SetupKeyRequest
	deletes int
	posts   int
}

func (k *keyServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/setup-keys/sk-1":
			w.Write([]byte(k.key))
		case r.Method == http.MethodPut && r.URL.Path == "/api/setup-keys/sk-1":
			var body api.SetupKeyRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("bad PUT body: %v", err)
			}
			k.puts = append(k.puts, body)
			w.Write([]byte(k.key))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/setup-keys/sk-1":
			k.deletes++
			w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/setup-keys":
			k.posts++
			w.Write([]byte(`{"id":"sk-1","key":"secret","name":"k","revoked":false,"expires":"2099-01-01T00:00:00Z","last_used":"2026-01-01T00:00:00Z","state":"valid","type":"reusable","auto_groups":[]}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}
}

func setupKeyJSON(revoked bool, expires string, groups string) string {
	return `{"id":"sk-1","name":"k","revoked":` + strconv.FormatBool(revoked) + `,"expires":"` + expires +
		`","last_used":"2026-01-01T00:00:00Z","state":"valid","type":"reusable","auto_groups":` + groups + `}`
}

func newKeyCR(revoked bool, groups []string) *v1alpha1.NbSetupKey {
	cr := &v1alpha1.NbSetupKey{ObjectMeta: metav1.ObjectMeta{Name: "tenant-k"}}
	cr.Spec.ForProvider.Name = "k"
	cr.Spec.ForProvider.Revoked = revoked
	cr.Spec.ForProvider.AutoGroups = groups
	meta.SetExternalName(cr, "sk-1")
	return cr
}

const (
	future = "2099-01-01T00:00:00Z"
	past   = "2020-01-01T00:00:00Z"
)

func TestObserveRevokedAndGroups(t *testing.T) {
	cases := map[string]struct {
		specRevoked bool
		specGroups  []string
		key         string
		upToDate    bool
	}{
		"ValidKeyMatchesSpec":          {false, []string{"g1", "g2"}, setupKeyJSON(false, future, `["g2","g1"]`), true},
		"NilAndEmptyGroupsAreEqual":    {false, nil, setupKeyJSON(false, future, `[]`), true},
		"AutoGroupsDrift":              {false, []string{"g1"}, setupKeyJSON(false, future, `["g2"]`), false},
		"SpecRevokedKeyStillValid":     {true, nil, setupKeyJSON(false, future, `[]`), false},
		"SpecRevokedKeyRevoked":        {true, nil, setupKeyJSON(true, future, `[]`), true},
		"SpecRevokedKeyExpired":        {true, nil, setupKeyJSON(false, past, `[]`), true},
		"SpecRevokedIgnoresGroupDrift": {true, []string{"g1"}, setupKeyJSON(true, future, `[]`), true},
		"KeyRevokedOutsideSpecRotates": {false, nil, setupKeyJSON(true, future, `[]`), false},
		"KeyExpiredRotates":            {false, nil, setupKeyJSON(false, past, `[]`), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ks := &keyServer{key: tc.key}
			auth, srv := newFakeAuth(t, ks.handler(t))
			defer srv.Close()
			e := external{authManager: auth}
			obs, err := e.Observe(context.Background(), newKeyCR(tc.specRevoked, tc.specGroups))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !obs.ResourceExists || obs.ResourceUpToDate != tc.upToDate {
				t.Errorf("want exists=true upToDate=%v, got %+v", tc.upToDate, obs)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	t.Run("RevokeInPlace", func(t *testing.T) {
		ks := &keyServer{key: setupKeyJSON(false, future, `["g1"]`)}
		auth, srv := newFakeAuth(t, ks.handler(t))
		defer srv.Close()
		e := external{authManager: auth}
		cr := newKeyCR(true, []string{"g1"})
		if _, err := e.Update(context.Background(), cr); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if ks.deletes != 0 || len(ks.puts) != 1 || !ks.puts[0].Revoked {
			t.Fatalf("want one revoking PUT and no DELETE, got puts=%+v deletes=%d", ks.puts, ks.deletes)
		}
		if meta.GetExternalName(cr) != "sk-1" {
			t.Errorf("revoke must keep the key identity, external-name=%q", meta.GetExternalName(cr))
		}
	})

	t.Run("AutoGroupsInPlace", func(t *testing.T) {
		ks := &keyServer{key: setupKeyJSON(false, future, `["g1"]`)}
		auth, srv := newFakeAuth(t, ks.handler(t))
		defer srv.Close()
		e := external{authManager: auth}
		if _, err := e.Update(context.Background(), newKeyCR(false, []string{"g1", "g2"})); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if ks.deletes != 0 || len(ks.puts) != 1 || ks.puts[0].Revoked || len(ks.puts[0].AutoGroups) != 2 {
			t.Fatalf("want one non-revoking PUT with both groups, got puts=%+v deletes=%d", ks.puts, ks.deletes)
		}
	})

	t.Run("NilGroupsSendEmptyList", func(t *testing.T) {
		ks := &keyServer{key: setupKeyJSON(false, future, `[]`)}
		auth, srv := newFakeAuth(t, ks.handler(t))
		defer srv.Close()
		e := external{authManager: auth}
		if _, err := e.Update(context.Background(), newKeyCR(true, nil)); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(ks.puts) != 1 || ks.puts[0].AutoGroups == nil {
			t.Fatalf("want auto_groups sent as [], got %+v", ks.puts)
		}
	})

	t.Run("RevokedKeyWithValidSpecRotates", func(t *testing.T) {
		ks := &keyServer{key: setupKeyJSON(true, future, `[]`)}
		auth, srv := newFakeAuth(t, ks.handler(t))
		defer srv.Close()
		e := external{authManager: auth}
		cr := newKeyCR(false, nil)
		cr.Status.AtProvider.Id = "sk-1"
		if _, err := e.Update(context.Background(), cr); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if ks.deletes != 1 || len(ks.puts) != 0 {
			t.Fatalf("want rotation (DELETE, no PUT), got puts=%+v deletes=%d", ks.puts, ks.deletes)
		}
		if meta.GetExternalName(cr) != "" || cr.Status.AtProvider.Id != "" {
			t.Errorf("rotation must clear identity so Create runs, got external-name=%q id=%q", meta.GetExternalName(cr), cr.Status.AtProvider.Id)
		}
	})
}

func TestCreateRevoked(t *testing.T) {
	ks := &keyServer{key: setupKeyJSON(false, future, `[]`)}
	auth, srv := newFakeAuth(t, ks.handler(t))
	defer srv.Close()
	e := external{authManager: auth}
	cr := newKeyCR(true, nil)
	meta.SetExternalName(cr, "")
	if _, err := e.Create(context.Background(), cr); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ks.posts != 1 || len(ks.puts) != 1 || !ks.puts[0].Revoked {
		t.Fatalf("want POST then revoking PUT, got posts=%d puts=%+v", ks.posts, ks.puts)
	}
}

func TestObserveAdoptionRevokedSpec(t *testing.T) {
	old := `{"id":"sk-old","name":"k","revoked":true,"expires":"2099-01-01T00:00:00Z","last_used":"2026-01-01T00:00:00Z","state":"revoked","type":"reusable","auto_groups":[]}`
	live := `{"id":"sk-live","name":"k","revoked":false,"expires":"2099-01-01T00:00:00Z","last_used":"2026-01-01T00:00:00Z","state":"valid","type":"reusable","auto_groups":[]}`
	for name, tc := range map[string]struct {
		list   string
		wantID string
	}{
		"PrefersValidKeySoItGetsRevoked": {"[" + old + "," + live + "]", "sk-live"},
		"FallsBackToRevokedKey":          {"[" + old + "]", "sk-old"},
	} {
		t.Run(name, func(t *testing.T) {
			auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/setup-keys" && r.Method == http.MethodGet {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(tc.list))
					return
				}
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			})
			defer srv.Close()
			e := external{authManager: auth}
			cr := &v1alpha1.NbSetupKey{ObjectMeta: metav1.ObjectMeta{Name: "tenant-k"}}
			cr.Spec.ForProvider.Name = "k"
			cr.Spec.ForProvider.Revoked = true
			obs, err := e.Observe(context.Background(), cr)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !obs.ResourceExists || cr.Status.AtProvider.Id != tc.wantID {
				t.Errorf("want adoption of %s, got id=%q obs=%+v", tc.wantID, cr.Status.AtProvider.Id, obs)
			}
		})
	}
}
