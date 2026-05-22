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

package nbnetwork

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crossplane/crossplane-runtime/pkg/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"

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

func TestResolveNetworkLookupID(t *testing.T) {
	cases := map[string]struct {
		cr   *v1alpha1.NbNetwork
		want string
	}{
		"EmptyExternalNameWithStatusID": {
			cr: func() *v1alpha1.NbNetwork {
				n := &v1alpha1.NbNetwork{}
				n.Status.AtProvider.Id = "real-id"
				return n
			}(),
			want: "real-id",
		},
		"EmptyExternalNameAndEmptyStatus": {
			cr:   &v1alpha1.NbNetwork{},
			want: "",
		},
		"ExternalNameDefaultedToObjectNameRecoversFromStatus": {
			cr: func() *v1alpha1.NbNetwork {
				n := &v1alpha1.NbNetwork{
					ObjectMeta: metav1.ObjectMeta{Name: "my-net"},
				}
				meta.SetExternalName(n, "my-net")
				n.Status.AtProvider.Id = "real-id"
				return n
			}(),
			want: "real-id",
		},
		"ExternalNameSetToRealID": {
			cr: func() *v1alpha1.NbNetwork {
				n := &v1alpha1.NbNetwork{
					ObjectMeta: metav1.ObjectMeta{Name: "my-net"},
				}
				meta.SetExternalName(n, "real-id")
				return n
			}(),
			want: "real-id",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := resolveNetworkLookupID(tc.cr); got != tc.want {
				t.Errorf("resolveNetworkLookupID() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsNetworkNotFoundError(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"NilError":            {err: nil, want: false},
		"UnrelatedError":      {err: errors.New("kaboom"), want: false},
		"NetworkNotFound":     {err: errors.New("network: abc not found"), want: true},
		"CaseInsensitive":     {err: errors.New("Network NOT FOUND"), want: true},
		"OnlyContainsNetwork": {err: errors.New("network: invalid request"), want: false},
		"OnlyContainsNotFound": {
			err: errors.New("group: abc not found"), want: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := isNetworkNotFoundError(tc.err); got != tc.want {
				t.Errorf("isNetworkNotFoundError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestObserve(t *testing.T) {
	t.Run("EmptyExternalNameAndEmptyStatusReturnsResourceExistsFalse", func(t *testing.T) {
		// No HTTP traffic should occur because the by-name adoption path lists
		// networks and finds nothing matching the spec name.
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/networks" && r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[]`))
				return
			}
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetwork{
			ObjectMeta: metav1.ObjectMeta{Name: "my-net"},
		}
		cr.Spec.ForProvider.Name = "my-net"

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
			if r.URL.Path == "/api/networks/real-id" && r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"message":"network: real-id not found","code":404}`))
				return
			}
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetwork{ObjectMeta: metav1.ObjectMeta{Name: "k8s-name"}}
		meta.SetExternalName(cr, "real-id")

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
			// Return a 503 with a body that does NOT look like a not-found.
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"message":"upstream unavailable","code":503}`))
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetwork{ObjectMeta: metav1.ObjectMeta{Name: "k8s-name"}}
		meta.SetExternalName(cr, "real-id")

		obs, err := e.Observe(context.Background(), cr)
		if err == nil {
			t.Fatalf("expected error on transient failure, got nil (obs=%+v)", obs)
		}
		if obs.ResourceExists {
			t.Errorf("expected ResourceExists=false on transient error (Create must not run), got %+v", obs)
		}
		if !strings.Contains(err.Error(), "failed to observe network") {
			t.Errorf("expected wrapped error mentioning network, got %v", err)
		}
	})

	t.Run("StaleExternalNameRepairedFromStatusID", func(t *testing.T) {
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/networks/real-id" && r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"id":"real-id","name":"my-net","description":"d"}`))
				return
			}
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetwork{ObjectMeta: metav1.ObjectMeta{Name: "my-net"}}
		// Simulate the older defaulted external-name scenario: external-name == k8s name.
		meta.SetExternalName(cr, "my-net")
		cr.Status.AtProvider.Id = "real-id"
		cr.Spec.ForProvider.Name = "my-net"
		cr.Spec.ForProvider.Description = "d"

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
