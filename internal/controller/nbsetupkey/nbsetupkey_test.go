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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"

	auth "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
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
