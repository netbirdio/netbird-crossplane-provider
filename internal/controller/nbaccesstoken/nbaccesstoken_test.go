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

package nbaccesstoken

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

// Unlike many Kubernetes projects Crossplane does not use third party testing
// libraries, per the common Go test review comments. Crossplane encourages the
// use of table driven unit tests. The tests of the crossplane-runtime project
// are representative of the testing style Crossplane encourages.
//
// https://github.com/golang/go/wiki/TestComments
// https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md#contributing-code

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

// TestObserveAdoption covers adoption by name under the resolved user, which
// prevents a Create whose external-name persist failed from minting a
// duplicate PAT.
func TestObserveAdoption(t *testing.T) {
	t.Run("EmptyLookupAdoptsTokenByNameUnderUser", func(t *testing.T) {
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/users" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"u-1","name":"svc-user","is_service_user":true,"email":"","role":"admin","auto_groups":[],"is_blocked":false,"issued":"api","status":"active"}]`))
			case r.URL.Path == "/api/users/u-1/tokens" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"t-1","name":"bootstrap-pat","expiration_date":"2099-01-01T00:00:00Z","created_by":"u-1","created_at":"2026-01-01T00:00:00Z"}]`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		userName := "svc-user"
		e := external{authManager: auth}
		cr := &v1alpha1.NbAccessToken{ObjectMeta: metav1.ObjectMeta{Name: "tenant-bootstrap-pat"}}
		cr.Spec.ForProvider.Name = "bootstrap-pat"
		cr.Spec.ForProvider.UserName = &userName

		obs, err := e.Observe(context.Background(), cr)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !obs.ResourceExists {
			t.Fatalf("expected adoption (ResourceExists=true), got %+v", obs)
		}
		if !obs.ResourceUpToDate {
			t.Errorf("expected up-to-date on adoption (Update would rotate the token), got %+v", obs)
		}
		if cr.Status.AtProvider.Id != "t-1" {
			t.Errorf("expected status.atProvider.id 't-1', got %q", cr.Status.AtProvider.Id)
		}
	})

	t.Run("NoMatchingTokenReturnsResourceExistsFalse", func(t *testing.T) {
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/users" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"u-1","name":"svc-user","is_service_user":true,"email":"","role":"admin","auto_groups":[],"is_blocked":false,"issued":"api","status":"active"}]`))
			case r.URL.Path == "/api/users/u-1/tokens" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[]`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		userName := "svc-user"
		e := external{authManager: auth}
		cr := &v1alpha1.NbAccessToken{ObjectMeta: metav1.ObjectMeta{Name: "tenant-bootstrap-pat"}}
		cr.Spec.ForProvider.Name = "bootstrap-pat"
		cr.Spec.ForProvider.UserName = &userName

		obs, err := e.Observe(context.Background(), cr)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if obs.ResourceExists {
			t.Errorf("expected ResourceExists=false with no matching token, got %+v", obs)
		}
	})
}
