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

package nbnetworkresource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	nbapi "github.com/netbirdio/netbird/shared/management/http/api"
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

// TestResolveNetworkResourceLookupID exercises the lookup-ID resolver helper.
func TestResolveNetworkResourceLookupID(t *testing.T) {
	cases := map[string]struct {
		cr   *v1alpha1.NbNetworkResource
		want string
	}{
		"EmptyExternalNameWithStatusID": {
			cr: func() *v1alpha1.NbNetworkResource {
				n := &v1alpha1.NbNetworkResource{}
				n.Status.AtProvider.Id = "real-id"
				return n
			}(),
			want: "real-id",
		},
		"EmptyExternalNameAndEmptyStatus": {
			cr:   &v1alpha1.NbNetworkResource{},
			want: "",
		},
		"ExternalNameDefaultedToObjectNameRecoversFromStatus": {
			cr: func() *v1alpha1.NbNetworkResource {
				n := &v1alpha1.NbNetworkResource{
					ObjectMeta: metav1.ObjectMeta{Name: "my-res"},
				}
				meta.SetExternalName(n, "my-res")
				n.Status.AtProvider.Id = "real-id"
				return n
			}(),
			want: "real-id",
		},
		"ExternalNameSetToRealID": {
			cr: func() *v1alpha1.NbNetworkResource {
				n := &v1alpha1.NbNetworkResource{
					ObjectMeta: metav1.ObjectMeta{Name: "my-res"},
				}
				meta.SetExternalName(n, "real-id")
				return n
			}(),
			want: "real-id",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := resolveNetworkResourceLookupID(tc.cr); got != tc.want {
				t.Errorf("resolveNetworkResourceLookupID() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIsNetworkResourceNotFoundError exercises the not-found error matcher.
func TestIsNetworkResourceNotFoundError(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"NilError":         {err: nil, want: false},
		"UnrelatedError":   {err: errors.New("kaboom"), want: false},
		"ResourceNotFound": {err: errors.New("resource: abc not found"), want: true},
		"CaseInsensitive":  {err: errors.New("Resource NOT FOUND"), want: true},
		"OnlyContainsResource": {
			err: errors.New("resource: invalid request"), want: false,
		},
		"OnlyContainsNotFound": {
			err: errors.New("group: abc not found"), want: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := isNetworkResourceNotFoundError(tc.err); got != tc.want {
				t.Errorf("isNetworkResourceNotFoundError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestObserve covers the Observe code paths in this controller.
func TestObserve(t *testing.T) {
	t.Run("EmptyExternalNameAndEmptyStatusReturnsResourceExistsFalse", func(t *testing.T) {
		// Network listing returns one network so adoption can run, then resource
		// listing returns no matching resource -> ResourceExists: false.
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/networks" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"net-1","name":"my-net"}]`))
			case r.URL.Path == "/api/networks/net-1/resources" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[]`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetworkResource{ObjectMeta: metav1.ObjectMeta{Name: "my-res"}}
		cr.Spec.ForProvider.Name = "my-res"
		cr.Spec.ForProvider.NetworkName = "my-net"

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
			case r.URL.Path == "/api/networks/net-1/resources/real-id" && r.Method == http.MethodGet:
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"message":"resource: real-id not found","code":404}`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetworkResource{ObjectMeta: metav1.ObjectMeta{Name: "k8s-name"}}
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
			case r.URL.Path == "/api/networks/net-1/resources/real-id" && r.Method == http.MethodGet:
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"message":"upstream unavailable","code":503}`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetworkResource{ObjectMeta: metav1.ObjectMeta{Name: "k8s-name"}}
		meta.SetExternalName(cr, "real-id")
		cr.Spec.ForProvider.NetworkName = "my-net"

		obs, err := e.Observe(context.Background(), cr)
		if err == nil {
			t.Fatalf("expected error on transient failure, got nil (obs=%+v)", obs)
		}
		if obs.ResourceExists {
			t.Errorf("expected ResourceExists=false on transient error (Create must not run), got %+v", obs)
		}
		if !strings.Contains(err.Error(), "failed to observe network resource") {
			t.Errorf("expected wrapped error mentioning network resource, got %v", err)
		}
	})

	t.Run("StaleExternalNameRepairedFromStatusID", func(t *testing.T) {
		auth, srv := newFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/networks" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[{"id":"net-1","name":"my-net"}]`))
			case r.URL.Path == "/api/networks/net-1/resources/real-id" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"id":"real-id","name":"my-res","enabled":true,"address":"1.1.1.1/32","type":"host"}`))
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		})
		defer srv.Close()

		e := external{authManager: auth}
		cr := &v1alpha1.NbNetworkResource{ObjectMeta: metav1.ObjectMeta{Name: "my-res"}}
		// Older defaulted external-name scenario: external-name == k8s name.
		meta.SetExternalName(cr, "my-res")
		cr.Status.AtProvider.Id = "real-id"
		cr.Spec.ForProvider.Name = "my-res"
		cr.Spec.ForProvider.NetworkName = "my-net"

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

// TestResolveGroupIDs exercises the spec-to-API group ID resolver.
func TestResolveGroupIDs(t *testing.T) {
	strp := func(s string) *string { return &s }
	api := []nbapi.Group{
		{Id: "g-all", Name: "All"},
		{Id: "g-bao", Name: "bao-routers"},
	}
	cases := map[string]struct {
		spec    []v1alpha1.GroupMinimum
		want    []string
		wantErr bool
	}{
		"by id wins over name": {
			spec: []v1alpha1.GroupMinimum{{Id: strp("g-bao"), Name: strp("ignored")}},
			want: []string{"g-bao"},
		},
		"by name resolves to api id": {
			spec: []v1alpha1.GroupMinimum{{Name: strp("bao-routers")}},
			want: []string{"g-bao"},
		},
		"name nil falls through to error if id also nil": {
			spec:    []v1alpha1.GroupMinimum{{}},
			wantErr: true,
		},
		"name not found in api groups errors": {
			spec:    []v1alpha1.GroupMinimum{{Name: strp("does-not-exist")}},
			wantErr: true,
		},
		"empty spec is empty result": {
			spec: []v1alpha1.GroupMinimum{},
			want: []string{},
		},
		"id with empty string falls back to name": {
			spec: []v1alpha1.GroupMinimum{{Id: strp(""), Name: strp("All")}},
			want: []string{"g-all"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := resolveGroupIDs(tc.spec, api)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil; got=%v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("resolveGroupIDs(...): -want, +got:\n%s", diff)
			}
		})
	}
}
