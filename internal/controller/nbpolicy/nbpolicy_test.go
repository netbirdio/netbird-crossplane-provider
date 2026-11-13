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

package nbpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	auth "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	"github.com/go-logr/logr"
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

func strp(s string) *string { return &s }

func gm(id, name string) v1alpha1.GroupMinimum {
	g := v1alpha1.GroupMinimum{}
	if id != "" {
		g.Id = strp(id)
	}
	if name != "" {
		g.Name = strp(name)
	}
	return g
}

var testGroups = []nbapi.Group{
	{Id: "g-ops", Name: "ops"},
	{Id: "g-dev", Name: "dev"},
	{Id: "g-dup1", Name: "dup"},
	{Id: "g-dup2", Name: "dup"},
}

func TestNbToApiGroupMinimums(t *testing.T) {
	cases := map[string]struct {
		in      *[]v1alpha1.GroupMinimum
		want    *[]string
		wantErr string
	}{
		"Nil": {in: nil, want: nil},
		"ByID": {
			in:   &[]v1alpha1.GroupMinimum{gm("g-ops", "")},
			want: &[]string{"g-ops"},
		},
		"ByName": {
			in:   &[]v1alpha1.GroupMinimum{gm("", "dev")},
			want: &[]string{"g-dev"},
		},
		"Mixed": {
			in:   &[]v1alpha1.GroupMinimum{gm("", "dev"), gm("g-ops", ""), gm("g-dup1", "dup")},
			want: &[]string{"g-dev", "g-ops", "g-dup1"},
		},
		"IDWinsOverName": {
			in:   &[]v1alpha1.GroupMinimum{gm("g-ops", "dev")},
			want: &[]string{"g-ops"},
		},
		"StaleIDFallsBackToName": {
			in:   &[]v1alpha1.GroupMinimum{gm("g-gone", "dev")},
			want: &[]string{"g-dev"},
		},
		"UnknownName": {
			in:      &[]v1alpha1.GroupMinimum{gm("", "dev"), gm("", "nope")},
			wantErr: `group not found by name: "nope"`,
		},
		"UnknownID": {
			in:      &[]v1alpha1.GroupMinimum{gm("g-gone", "")},
			wantErr: `group not found by id: "g-gone"`,
		},
		"DuplicateName": {
			in:      &[]v1alpha1.GroupMinimum{gm("", "dup")},
			wantErr: `group name "dup" is ambiguous: 2 groups carry it (ids g-dup1, g-dup2); reference it by id`,
		},
		"Empty": {
			in:      &[]v1alpha1.GroupMinimum{{}},
			wantErr: "group reference missing both id and name",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := NbToApiGroupMinimums(tc.in, testGroups)
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tc.wantErr {
				t.Fatalf("error: want %q, got %q", tc.wantErr, gotErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("NbToApiGroupMinimums(...): -want, +got:\n%s", diff)
			}
		})
	}
}

func apiRule(sources, destinations []nbapi.GroupMinimum) nbapi.Policy {
	return nbapi.Policy{Rules: []nbapi.PolicyRule{{
		Action:        "accept",
		Bidirectional: true,
		Protocol:      "all",
		Sources:       &sources,
		Destinations:  &destinations,
	}}}
}

func specRule(sources, destinations []v1alpha1.GroupMinimum) v1alpha1.NbPolicyParameters {
	return v1alpha1.NbPolicyParameters{Rules: []v1alpha1.PolicyRule{{
		Action:        "accept",
		Bidirectional: true,
		Protocol:      "all",
		Sources:       &sources,
		Destinations:  &destinations,
	}}}
}

func TestIsApiToNBPolicyUpToDateGroups(t *testing.T) {
	api := apiRule(
		[]nbapi.GroupMinimum{{Id: "g-ops", Name: "ops"}},
		[]nbapi.GroupMinimum{{Id: "g-dev", Name: "dev"}, {Id: "g-dup2", Name: "dup"}},
	)
	cases := map[string]struct {
		spec v1alpha1.NbPolicyParameters
		want bool
	}{
		"ByIDMatches": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("g-ops", "")}, []v1alpha1.GroupMinimum{gm("g-dev", ""), gm("g-dup2", "")}),
			want: true,
		},
		"NameOnlyMatches": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "ops")}, []v1alpha1.GroupMinimum{gm("", "dev"), gm("g-dup2", "")}),
			want: true,
		},
		"NameOnlyDiffers": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "dev")}, []v1alpha1.GroupMinimum{gm("", "dev"), gm("g-dup2", "")}),
			want: false,
		},
		"OrderDiffers": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "ops")}, []v1alpha1.GroupMinimum{gm("g-dup2", ""), gm("", "dev")}),
			want: false,
		},
		"UnresolvableName": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "nope")}, []v1alpha1.GroupMinimum{gm("", "dev"), gm("g-dup2", "")}),
			want: false,
		},
		"AmbiguousName": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "ops")}, []v1alpha1.GroupMinimum{gm("", "dev"), gm("", "dup")}),
			want: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{log: logr.Discard()}
			if got := IsApiToNBPolicyUpToDate(tc.spec, &api, testGroups, e); got != tc.want {
				t.Errorf("IsApiToNBPolicyUpToDate(...) = %v, want %v", got, tc.want)
			}
		})
	}
}

func gmi(name, issued string) v1alpha1.GroupMinimum {
	g := gm("", name)
	g.Issued = strp(issued)
	return g
}

func TestResolveGroupIDIssued(t *testing.T) {
	api, jwt := nbapi.GroupIssuedApi, nbapi.GroupIssuedJwt
	groups := []nbapi.Group{
		{Id: "g-api", Name: "eng", Issued: &api},
		{Id: "g-jwt", Name: "eng", Issued: &jwt},
		{Id: "g-ops", Name: "ops", Issued: &api},
	}
	cases := map[string]struct {
		in      v1alpha1.GroupMinimum
		groups  []nbapi.Group
		want    string
		wantErr string
	}{
		"NameAndIssuedPicksOrigin": {in: gmi("eng", "jwt"), want: "g-jwt"},
		"NoGroupOfThatOrigin": {
			in:      gmi("ops", "jwt"),
			wantErr: `group not found by name: "ops" issued "jwt"`,
		},
		"EmptyIssuedIgnored": {in: gmi("ops", ""), want: "g-ops"},
		"NameAndIssuedAmbiguous": {
			in:      gmi("eng", "api"),
			groups:  append(groups, nbapi.Group{Id: "g-api2", Name: "eng", Issued: &api}),
			wantErr: `group name "eng" issued "api" is ambiguous: 2 groups carry it (ids g-api, g-api2); reference it by id`,
		},
		"IssuedUnsetAmbiguous": {
			in:      gm("", "eng"),
			wantErr: `group name "eng" is ambiguous: 2 groups carry it (ids g-api, g-jwt); reference it by id`,
		},
		"ByIDIgnoresIssued": {
			in:   v1alpha1.GroupMinimum{Id: strp("g-api"), Issued: strp("jwt")},
			want: "g-api",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gs := groups
			if tc.groups != nil {
				gs = tc.groups
			}
			got, err := resolveGroupID(tc.in, gs)
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tc.wantErr || got != tc.want {
				t.Errorf("resolveGroupID(...) = %q, %q; want %q, %q", got, gotErr, tc.want, tc.wantErr)
			}
		})
	}
}

func TestNbToApiRulesErrorNamesRule(t *testing.T) {
	cases := map[string]struct {
		rule    v1alpha1.PolicyRule
		wantErr string
	}{
		"NamedSources": {
			rule:    v1alpha1.PolicyRule{Name: "web", Sources: &[]v1alpha1.GroupMinimum{gm("", "nope")}},
			wantErr: `rule "web" sources: group not found by name: "nope"`,
		},
		"UnnamedDestinations": {
			rule:    v1alpha1.PolicyRule{Destinations: &[]v1alpha1.GroupMinimum{gm("", "nope")}},
			wantErr: `rule 1 destinations: group not found by name: "nope"`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rules := []v1alpha1.PolicyRule{{Name: "ok"}, tc.rule}
			_, err := NbToApiRules(&rules, testGroups)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("NbToApiRules(...) error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func ids(ids ...string) []nbapi.GroupMinimum {
	out := []nbapi.GroupMinimum{}
	for _, id := range ids {
		out = append(out, nbapi.GroupMinimum{Id: id})
	}
	return out
}

func refs(names ...string) *[]v1alpha1.GroupMinimum {
	out := []v1alpha1.GroupMinimum{}
	for _, n := range names {
		out = append(out, gm("", n))
	}
	return &out
}

func TestIsApiToNBPolicyUpToDateSourcesStrict(t *testing.T) {
	groups := []nbapi.Group{
		{Id: "g-ops", Name: "ops"}, {Id: "g-dev", Name: "dev"}, {Id: "g-db", Name: "db"},
	}
	type rule struct{ src, dst []nbapi.GroupMinimum }
	apiPolicy := func(rs ...rule) *nbapi.Policy {
		p := &nbapi.Policy{}
		for _, r := range rs {
			src, dst := r.src, r.dst
			p.Rules = append(p.Rules, nbapi.PolicyRule{Action: "accept", Sources: &src, Destinations: &dst})
		}
		return p
	}
	specPolicy := func(rs ...[2]*[]v1alpha1.GroupMinimum) v1alpha1.NbPolicyParameters {
		p := v1alpha1.NbPolicyParameters{}
		for _, r := range rs {
			p.Rules = append(p.Rules, v1alpha1.PolicyRule{Action: "accept", Sources: r[0], Destinations: r[1]})
		}
		return p
	}
	cases := map[string]struct {
		spec v1alpha1.NbPolicyParameters
		api  *nbapi.Policy
		want bool
	}{
		"SharedSourceDedupedByServer": {
			spec: specPolicy([2]*[]v1alpha1.GroupMinimum{refs("ops"), refs("dev")}, [2]*[]v1alpha1.GroupMinimum{refs("ops"), refs("db")}),
			api:  apiPolicy(rule{ids("g-ops"), ids("g-dev")}, rule{ids(), ids("g-db")}),
			want: false,
		},
		"SharedSourceInFull": {
			spec: specPolicy([2]*[]v1alpha1.GroupMinimum{refs("ops"), refs("dev")}, [2]*[]v1alpha1.GroupMinimum{refs("ops"), refs("db")}),
			api:  apiPolicy(rule{ids("g-ops"), ids("g-dev")}, rule{ids("g-ops"), ids("g-db")}),
			want: true,
		},
		"DifferentSource": {
			spec: specPolicy([2]*[]v1alpha1.GroupMinimum{refs("ops"), refs("dev")}, [2]*[]v1alpha1.GroupMinimum{refs("db"), refs("dev")}),
			api:  apiPolicy(rule{ids("g-ops"), ids("g-dev")}, rule{ids("g-ops"), ids("g-dev")}),
			want: false,
		},
		"DroppedSourceNotSeenBefore": {
			spec: specPolicy([2]*[]v1alpha1.GroupMinimum{refs("ops"), refs("dev")}, [2]*[]v1alpha1.GroupMinimum{refs("db"), refs("dev")}),
			api:  apiPolicy(rule{ids("g-ops"), ids("g-dev")}, rule{ids(), ids("g-dev")}),
			want: false,
		},
		"EarlierDestinationAsSourceDeduped": {
			spec: specPolicy([2]*[]v1alpha1.GroupMinimum{refs("ops"), refs("dev")}, [2]*[]v1alpha1.GroupMinimum{refs("dev", "db"), refs("ops")}),
			api:  apiPolicy(rule{ids("g-ops"), ids("g-dev")}, rule{ids("g-db"), ids("g-ops")}),
			want: false,
		},
		"DuplicateSourceInOneRuleDeduped": {
			spec: specPolicy([2]*[]v1alpha1.GroupMinimum{refs("ops", "ops"), refs("dev")}),
			api:  apiPolicy(rule{ids("g-ops"), ids("g-dev")}),
			want: false,
		},
		"NoGroupsNilAndEmpty": {
			spec: specPolicy([2]*[]v1alpha1.GroupMinimum{nil, &[]v1alpha1.GroupMinimum{}}),
			api:  &nbapi.Policy{Rules: []nbapi.PolicyRule{{Action: "accept", Sources: &[]nbapi.GroupMinimum{}}}},
			want: true,
		},
		"NilSpecButAPIHasGroups": {
			spec: specPolicy([2]*[]v1alpha1.GroupMinimum{nil, refs("dev")}),
			api:  apiPolicy(rule{ids("g-ops"), ids("g-dev")}),
			want: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{log: logr.Discard()}
			if got := IsApiToNBPolicyUpToDate(tc.spec, tc.api, groups, e); got != tc.want {
				t.Errorf("IsApiToNBPolicyUpToDate(...) = %v, want %v", got, tc.want)
			}
		})
	}
}

type fakeAuthClient struct{ client *netbird.Client }

func (f *fakeAuthClient) GetClient(_ context.Context) (*netbird.Client, error) { return f.client, nil }
func (f *fakeAuthClient) ForceRefresh(_ context.Context) error                 { return nil }

// TestObserveDeletingSkipsGroups: a failing group listing blocks Observe of a
// live policy but not of one being deleted.
func TestObserveDeletingSkipsGroups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/policies/p1":
			_ = json.NewEncoder(w).Encode(nbapi.Policy{Id: strp("p1"), Name: "pol"})
		default:
			http.Error(w, `{"message":"boom","code":500}`, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	e := &external{
		authManager: &fakeAuthClient{netbird.NewWithOptions(netbird.WithManagementURL(srv.URL), netbird.WithPAT("t"))},
		log:         logr.Discard(),
	}
	for name, deleting := range map[string]bool{"Deleting": true, "Live": false} {
		t.Run(name, func(t *testing.T) {
			cr := &v1alpha1.NbPolicy{}
			cr.SetName("k8s-name")
			cr.Spec.ForProvider.Name = "pol"
			meta.SetExternalName(cr, "p1")
			if deleting {
				now := metav1.Now()
				cr.SetDeletionTimestamp(&now)
			}
			got, err := e.Observe(context.Background(), cr)
			if deleting && (err != nil || !got.ResourceExists) {
				t.Errorf("Observe(deleting) = %+v, %v; want exists, no error", got, err)
			}
			if !deleting && err == nil {
				t.Errorf("Observe(live) error = nil, want the group listing error")
			}
		})
	}
}
