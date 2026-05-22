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

package nbnetworkrouter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netbird "github.com/netbirdio/netbird/management/client/rest"
)

// Unlike many Kubernetes projects Crossplane does not use third party testing
// libraries, per the common Go test review comments. Crossplane encourages the
// use of table driven unit tests. The tests of the crossplane-runtime project
// are representative of the testing style Crossplane encourages.
//
// https://github.com/golang/go/wiki/TestComments
// https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md#contributing-code

// fakeAuthClient satisfies the authClient interface and returns a real netbird
// client pointed at an httptest server.
type fakeAuthClient struct {
	client *netbird.Client
}

func (f *fakeAuthClient) GetClient(_ context.Context) (*netbird.Client, error) {
	return f.client, nil
}
func (f *fakeAuthClient) ForceRefresh(_ context.Context) error { return nil }

func newFakeAuth(t *testing.T, h http.HandlerFunc) (*fakeAuthClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	c := netbird.NewWithOptions(
		netbird.WithManagementURL(srv.URL),
		netbird.WithPAT("test-token"),
	)
	return &fakeAuthClient{client: c}, srv
}

func TestResolveNetworkRouterLookupID(t *testing.T) {
	cases := map[string]struct {
		cr   *v1alpha1.NbNetworkRouter
		want string
	}{
		"EmptyExternalNameWithStatusID": {
			cr: func() *v1alpha1.NbNetworkRouter {
				n := &v1alpha1.NbNetworkRouter{}
				n.Status.AtProvider.Id = "real-id"
				return n
			}(),
			want: "real-id",
		},
		"EmptyExternalNameAndEmptyStatus": {
			cr:   &v1alpha1.NbNetworkRouter{},
			want: "",
		},
		"ExternalNameDefaultedToObjectNameRecoversFromStatus": {
			cr: func() *v1alpha1.NbNetworkRouter {
				n := &v1alpha1.NbNetworkRouter{
					ObjectMeta: metav1.ObjectMeta{Name: "my-router"},
				}
				meta.SetExternalName(n, "my-router")
				n.Status.AtProvider.Id = "real-id"
				return n
			}(),
			want: "real-id",
		},
		"ExternalNameSetToRealID": {
			cr: func() *v1alpha1.NbNetworkRouter {
				n := &v1alpha1.NbNetworkRouter{
					ObjectMeta: metav1.ObjectMeta{Name: "my-router"},
				}
				meta.SetExternalName(n, "real-id")
				return n
			}(),
			want: "real-id",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := resolveNetworkRouterLookupID(tc.cr); got != tc.want {
				t.Errorf("resolveNetworkRouterLookupID() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsNetworkRouterNotFoundError(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"NilError":           {err: nil, want: false},
		"UnrelatedError":     {err: errors.New("kaboom"), want: false},
		"RouterNotFound":     {err: errors.New("router: abc not found"), want: true},
		"CaseInsensitive":    {err: errors.New("Router NOT FOUND"), want: true},
		"OnlyContainsRouter": {err: errors.New("router: invalid request"), want: false},
		"OnlyContainsNotFound": {
			err: errors.New("group: abc not found"), want: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := isNetworkRouterNotFoundError(tc.err); got != tc.want {
				t.Errorf("isNetworkRouterNotFoundError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestObserve(t *testing.T) {
	t.Run("EmptyExternalNameAndEmptyStatusReturnsResourceExistsFalse", func(t *testing.T) {
		// Network listing returns one network, routers list is empty so the by-group
		// adoption path falls through to ResourceExists: false.
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/networks" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"net-1","name":"my-net"}]`))
			case r.URL.Path == "/api/networks/net-1/routers" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[]`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetworkRouter{ObjectMeta: metav1.ObjectMeta{Name: "my-router"}}
		cr.Spec.ForProvider.NetworkName = "my-net"
		cr.Spec.ForProvider.PeerGroupName = "bao-routers"

		obs, err := e.Observe(context.Background(), cr)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if obs.ResourceExists {
			t.Errorf("expected ResourceExists=false, got %+v", obs)
		}
	})

	t.Run("ByIDNotFoundReturnsResourceExistsFalse", func(t *testing.T) {
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/networks" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"net-1","name":"my-net"}]`))
			case r.URL.Path == "/api/networks/net-1/routers/real-id" && r.Method == http.MethodGet:
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"message":"router: real-id not found","code":404}`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetworkRouter{ObjectMeta: metav1.ObjectMeta{Name: "k8s-name"}}
		meta.SetExternalName(cr, "real-id")
		cr.Spec.ForProvider.NetworkName = "my-net"

		obs, err := e.Observe(context.Background(), cr)
		if err != nil {
			t.Fatalf("expected no error for not-found, got %v", err)
		}
		if obs.ResourceExists {
			t.Errorf("expected ResourceExists=false on not-found, got %+v", obs)
		}
	})

	t.Run("ByIDTransientErrorReturnsErrorNotResourceExistsFalse", func(t *testing.T) {
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/networks" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"net-1","name":"my-net"}]`))
			case r.URL.Path == "/api/networks/net-1/routers/real-id" && r.Method == http.MethodGet:
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"message":"upstream unavailable","code":503}`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetworkRouter{ObjectMeta: metav1.ObjectMeta{Name: "k8s-name"}}
		meta.SetExternalName(cr, "real-id")
		cr.Spec.ForProvider.NetworkName = "my-net"

		obs, err := e.Observe(context.Background(), cr)
		if err == nil {
			t.Fatalf("expected error on transient failure, got nil (obs=%+v)", obs)
		}
		if obs.ResourceExists {
			t.Errorf("expected ResourceExists=false on transient error (Create must not run), got %+v", obs)
		}
		if !strings.Contains(err.Error(), "failed to observe network router") {
			t.Errorf("expected wrapped error mentioning network router, got %v", err)
		}
	})

	t.Run("StaleExternalNameRepairedFromStatusID", func(t *testing.T) {
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/networks" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"net-1","name":"my-net"}]`))
			case r.URL.Path == "/api/networks/net-1/routers/real-id" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				// Single peer_groups entry so the observation populates PeerGroup.
				w.Write([]byte(`{"id":"real-id","enabled":true,"masquerade":false,"metric":9999,"peer_groups":["g-1"]}`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetworkRouter{ObjectMeta: metav1.ObjectMeta{Name: "my-router"}}
		// Older defaulted external-name scenario: external-name == k8s name.
		meta.SetExternalName(cr, "my-router")
		cr.Status.AtProvider.Id = "real-id"
		cr.Spec.ForProvider.NetworkName = "my-net"
		cr.Spec.ForProvider.PeerGroupName = "bao-routers"

		obs, err := e.Observe(context.Background(), cr)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !obs.ResourceExists {
			t.Errorf("expected ResourceExists=true after recovery, got %+v", obs)
		}
		if got := meta.GetExternalName(cr); got != "real-id" {
			t.Errorf("expected external-name repaired to 'real-id', got %q", got)
		}
	})
}
