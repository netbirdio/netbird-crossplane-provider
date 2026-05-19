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
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	auth "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
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
