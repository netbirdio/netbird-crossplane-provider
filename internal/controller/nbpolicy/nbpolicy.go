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
	"fmt"
	"reflect"
	"strings"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/feature"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	apisv1alpha1 "github.com/crossplane/netbird-crossplane-provider/apis/v1alpha1"
	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	auth "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	"github.com/crossplane/netbird-crossplane-provider/internal/features"
	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	nbapi "github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	errNotNbPolicy  = "managed resource is not a NbPolicy custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"
)

// Setup adds a controller that reconciles NbPolicy managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbPolicyGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOptions := []managed.ReconcilerOption{
		managed.WithExternalConnecter(&connector{
			SharedConnector: auth.NewSharedConnector(
				mgr.GetClient(),
				resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			),
		}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...),
		managed.WithInitializers(),
	}
	if o.Features.Enabled(feature.EnableBetaManagementPolicies) {
		reconcilerOptions = append(reconcilerOptions, managed.WithManagementPolicies())
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.NbPolicyGroupVersionKind),
		reconcilerOptions...,
	)
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbPolicy{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	*auth.SharedConnector
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	_, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return nil, errors.New(errNotNbPolicy)
	}

	pc, err := c.SharedConnector.GetProviderConfig(ctx, mg)
	if err != nil {
		return nil, err
	}

	authManager, err := c.SharedConnector.Connect(ctx, mg, pc)
	if err != nil {
		return nil, err
	}

	return &external{
		authManager: authManager,
		log:         ctrl.Log.WithName("provider-nbpolicy"),
	}, nil
}

// authClient is the subset of the netbird auth manager used by this controller.
type authClient interface {
	GetClient(ctx context.Context) (*netbird.Client, error)
	ForceRefresh(ctx context.Context) error
}

// external implements managed.ExternalClient for the NbPolicy managed resource.
type external struct {
	authManager authClient
	log         logr.Logger
}

// Observe checks whether the NbPolicy currently exists in netbird and updates status.
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbPolicy)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Observing", "cr", cr)

	externalName := meta.GetExternalName(cr)
	lookupID := resolvePolicyLookupID(cr)

	// The external-name annotation is not guaranteed to hold a provider ID (older
	// reconciles defaulted it to the object name, or it may hold a netbird display
	// name used as an adoption hint). Try the lookup ID as an ID first, and on
	// not-found fall back to adoption by Name.
	var policy *nbapi.Policy
	if lookupID != "" && lookupID != cr.Name && lookupID != cr.Spec.ForProvider.Name {
		var err error
		policy, err = client.Policies.Get(ctx, lookupID)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			if !isPolicyNotFoundError(err) {
				// Don't swallow transient errors — Crossplane should requeue, not call Create.
				return managed.ExternalObservation{}, errors.Wrapf(err, "failed to observe policy %q", lookupID)
			}
			c.log.Info("policy not found by id, attempting adoption by name", "lookup-id", lookupID)
		}
	}
	if policy == nil {
		// Adoption by Name: the netbird policy may exist even though we hold no
		// usable ID (fresh MR, or a Create whose external-name persist failed).
		c.log.Info("attempting adoption by Name", "name", cr.Spec.ForProvider.Name)
		policies, err := client.Policies.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to list policies for adoption")
		}
		for _, apipolicy := range policies {
			if apipolicy.Name == cr.Spec.ForProvider.Name {
				c.log.Info("found existing policy for adoption", "policyid", apipolicy.Id)
				if apipolicy.Id != nil {
					meta.SetExternalName(cr, *apipolicy.Id)
				}
				// Identity is persisted via status.atProvider.id (external-name set
				// during Observe is not persisted by the runtime), which the lookup
				// resolver prefers on subsequent reconciles.
				cr.Status.AtProvider.Id = apipolicy.Id
				return managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: false, // force a requeue for a fresh Observe
				}, nil
			}
		}
		// Not found, resource does not exist
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	// Repair stale or missing external-name annotations after recovering via status ID.
	if policy.Id != nil && externalName != *policy.Id {
		meta.SetExternalName(cr, *policy.Id)
	}

	// The spec may reference groups by name; resolve them against the current
	// group list so the comparison is by id. A resource being deleted skips the
	// comparison, so a failing group listing cannot block its deletion.
	uptodate := true
	if !meta.WasDeleted(cr) {
		groups, err := client.Groups.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to list groups")
		}
		uptodate = IsApiToNBPolicyUpToDate(cr.Spec.ForProvider, policy, groups, c)
	}
	cr.Status.AtProvider = v1alpha1.NbPolicyObservation{
		Id:                  policy.Id,
		Enabled:             policy.Enabled,
		Description:         policy.Description,
		Name:                policy.Name,
		Rules:               ApiToNBRules(policy.Rules),
		SourcePostureChecks: &policy.SourcePostureChecks,
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: uptodate,
	}, nil
}

// resolvePolicyLookupID picks the best identifier to use when looking the policy
// up by ID, falling back to the recorded provider ID when the external-name
// annotation is missing, was defaulted to the Kubernetes object name by an older
// reconcile (before WithInitializers disabled the NameAsExternalName default), or
// holds the netbird display name used as an adoption hint.
func resolvePolicyLookupID(cr *v1alpha1.NbPolicy) string {
	externalName := meta.GetExternalName(cr)
	statusID := ""
	if cr.Status.AtProvider.Id != nil {
		statusID = *cr.Status.AtProvider.Id
	}
	switch {
	case externalName == "":
		return statusID
	case statusID != "" && statusID != externalName &&
		(externalName == cr.GetName() || externalName == cr.Spec.ForProvider.Name):
		return statusID
	default:
		return externalName
	}
}

// isPolicyNotFoundError matches the "policy: <id> not found" / "policy not found"
// messages returned by the netbird REST API for a missing policy.
func isPolicyNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "policy") && strings.Contains(errStr, "not found")
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbPolicy)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Creating", "cr", cr)
	groups, err := client.Groups.List(ctx)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	rules, err := NbToApiRules(&cr.Spec.ForProvider.Rules, groups)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	policy, err := client.Policies.Create(ctx, nbapi.PostApiPoliciesJSONRequestBody{
		Name:                cr.Spec.ForProvider.Name,
		Description:         cr.Spec.ForProvider.Description,
		Enabled:             cr.Spec.ForProvider.Enabled,
		SourcePostureChecks: cr.Spec.ForProvider.SourcePostureChecks,
		Rules:               rules,
	})
	if err != nil {
		return managed.ExternalCreation{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
	meta.SetExternalName(cr, *policy.Id)
	return managed.ExternalCreation{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbPolicy)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Updating", "cr", cr)
	policyid := resolvePolicyLookupID(cr)
	if policyid == "" {
		return managed.ExternalUpdate{}, errors.New("can't find policy id")
	}
	groups, err := client.Groups.List(ctx)
	if err != nil {
		return managed.ExternalUpdate{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
	rules, err := NbToApiRules(&cr.Spec.ForProvider.Rules, groups)
	if err != nil {
		return managed.ExternalUpdate{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
	_, err = client.Policies.Update(ctx, policyid, nbapi.PutApiPoliciesPolicyIdJSONRequestBody{
		Name:                cr.Spec.ForProvider.Name,
		Description:         cr.Spec.ForProvider.Description,
		Enabled:             cr.Spec.ForProvider.Enabled,
		SourcePostureChecks: cr.Spec.ForProvider.SourcePostureChecks,
		Rules:               rules,
	})
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrapf(err, "failed to update policy %q", policyid)
	}
	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return errors.New(errNotNbPolicy)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Deleting", "cr", cr)
	policyid := resolvePolicyLookupID(cr)
	if policyid == "" {
		return errors.New("can't find policy id")
	}
	return client.Policies.Delete(ctx, policyid)
}

func NbToApiRules(policyRule *[]v1alpha1.PolicyRule, groups []nbapi.Group) ([]nbapi.PolicyRuleUpdate, error) {
	rules := make([]nbapi.PolicyRuleUpdate, len(*policyRule))
	for i, prule := range *policyRule {
		sources, destinations, err := resolveRuleGroups(i, prule, groups)
		if err != nil {
			return nil, err
		}
		rules[i] = nbapi.PolicyRuleUpdate{
			Action:        nbapi.PolicyRuleUpdateAction(prule.Action),
			Bidirectional: prule.Bidirectional,
			Description:   prule.Description,
			Destinations:  destinations,
			Enabled:       prule.Enabled,
			Id:            prule.Id,
			Name:          prule.Name,
			PortRanges:    NbToApiPortRanges(prule.PortRanges),
			Ports:         prule.Ports,
			Protocol:      nbapi.PolicyRuleUpdateProtocol(prule.Protocol),
			Sources:       sources,
		}
	}
	return rules, nil
}

func NbToApiPortRanges(rulePortRange *[]v1alpha1.RulePortRange) *[]nbapi.RulePortRange {
	if rulePortRange == nil {
		return nil
	}
	rportrange := make([]nbapi.RulePortRange, len(*rulePortRange))
	for i, rulePort := range *rulePortRange {
		rportrange[i] = nbapi.RulePortRange{
			End:   rulePort.End,
			Start: rulePort.Start,
		}
	}
	return &rportrange
}

// NbToApiGroupMinimums resolves the spec's group references into the group ids
// the netbird API expects, in spec order. Each entry is matched by Id first and,
// when the Id is absent or matches no group, by Name. Every entry must resolve:
// an unknown reference, or a Name carried by more than one group (netbird allows
// duplicate group names), is an error naming the entry, so the API is never sent
// an empty or arbitrarily chosen id. A nil list resolves to nil.
func NbToApiGroupMinimums(groupMinimums *[]v1alpha1.GroupMinimum, groups []nbapi.Group) (*[]string, error) {
	if groupMinimums == nil {
		return nil, nil
	}
	ids := make([]string, len(*groupMinimums))
	for i, gmin := range *groupMinimums {
		id, err := resolveGroupID(gmin, groups)
		if err != nil {
			return nil, err
		}
		ids[i] = id
	}
	return &ids, nil
}

// resolveRuleGroups resolves one rule's destinations and sources; an error
// names the rule (by name, or by index when unnamed) and the direction.
func resolveRuleGroups(i int, prule v1alpha1.PolicyRule, groups []nbapi.Group) (sources, destinations *[]string, err error) {
	label := fmt.Sprintf("rule %d", i)
	if prule.Name != "" {
		label = fmt.Sprintf("rule %q", prule.Name)
	}
	if destinations, err = NbToApiGroupMinimums(prule.Destinations, groups); err != nil {
		return nil, nil, errors.Wrapf(err, "%s destinations", label)
	}
	if sources, err = NbToApiGroupMinimums(prule.Sources, groups); err != nil {
		return nil, nil, errors.Wrapf(err, "%s sources", label)
	}
	return sources, destinations, nil
}

// resolveGroupID resolves one group reference against the account's groups.
// By name, a set Issued (api, integration, jwt) restricts the candidates to
// groups of that origin; resolution by Id ignores Issued.
func resolveGroupID(gmin v1alpha1.GroupMinimum, groups []nbapi.Group) (string, error) {
	hasID := gmin.Id != nil && *gmin.Id != ""
	hasName := gmin.Name != nil && *gmin.Name != ""
	if hasID {
		for _, group := range groups {
			if group.Id == *gmin.Id {
				return group.Id, nil
			}
		}
		if !hasName {
			return "", errors.Errorf("group not found by id: %q", *gmin.Id)
		}
	}
	if !hasName {
		return "", errors.New("group reference missing both id and name")
	}
	issued := ""
	if gmin.Issued != nil {
		issued = *gmin.Issued
	}
	var matched []string
	for _, group := range groups {
		if group.Name != *gmin.Name {
			continue
		}
		if issued != "" && (group.Issued == nil || string(*group.Issued) != issued) {
			continue
		}
		matched = append(matched, group.Id)
	}
	switch len(matched) {
	case 0:
		if issued != "" {
			return "", errors.Errorf("group not found by name: %q issued %q", *gmin.Name, issued)
		}
		return "", errors.Errorf("group not found by name: %q", *gmin.Name)
	case 1:
		return matched[0], nil
	default:
		label := fmt.Sprintf("group name %q", *gmin.Name)
		if issued != "" {
			label += fmt.Sprintf(" issued %q", issued)
		}
		return "", errors.Errorf("%s is ambiguous: %d groups carry it (ids %s); reference it by id", label, len(matched), strings.Join(matched, ", "))
	}
}

// groupIDsEqual reports whether the API rule's groups are, position by
// position, the given ids; a nil list equals an empty one.
func groupIDsEqual(api *[]v1alpha1.GroupMinimum, ids *[]string) bool {
	var a []v1alpha1.GroupMinimum
	var want []string
	if api != nil {
		a = *api
	}
	if ids != nil {
		want = *ids
	}
	if len(a) != len(want) {
		return false
	}
	for j, id := range want {
		if a[j].Id == nil || *a[j].Id != id {
			return false
		}
	}
	return true
}

func IsApiToNBPolicyUpToDate(nbPolicy v1alpha1.NbPolicyParameters, policy *nbapi.Policy, groups []nbapi.Group, c *external) bool {
	c.log.Info("Checking if API policy is up to date", "policy", policy)
	c.log.Info("Checking if API policy is up to date", "nbPolicy", nbPolicy)
	if nbPolicy.Rules == nil || policy.Rules == nil {
		c.log.Info("one of the rules is nil")
		return false
	}
	policyrules := ApiToNBRules(policy.Rules)
	if policyrules == nil || len(*policyrules) != len(nbPolicy.Rules) {
		c.log.Info("rules length doesn't match or rules is nil")
		return false
	}
	for i, policyrule := range *policyrules {
		c.log.Info("Checking if rules is up to date", "policyrule", policyrule)
		c.log.Info("Checking if rules is up to date", "nbPolicy.Rules[i]", nbPolicy.Rules[i])
		if !cmp.Equal(policyrule.Description, nbPolicy.Rules[i].Description) {
			c.log.Info("Description doesn't match")
			return false
		}
		if !cmp.Equal(policyrule.Action, string(nbPolicy.Rules[i].Action)) {
			c.log.Info("action doesn't match")
			return false
		}
		if !cmp.Equal(policyrule.Bidirectional, nbPolicy.Rules[i].Bidirectional) {
			c.log.Info("bidirectional doesn't match")
			return false
		}
		// Compare the API's group ids with the ids the spec resolves to, so a
		// group referenced by name only is compared too. A spec that cannot be
		// resolved never matches: the resulting Update surfaces the error.
		sources, destinations, err := resolveRuleGroups(i, nbPolicy.Rules[i], groups)
		if err != nil {
			c.log.Info("rule groups don't resolve", "error", err)
			return false
		}
		if !groupIDsEqual(policyrule.Destinations, destinations) {
			c.log.Info("destinations don't match")
			return false
		}
		// Known limitation: netbird's GET omits a source group already listed
		// earlier in the same policy (one group cache per policy in
		// toPolicyResponse), so a policy that reuses a source group across
		// rules, or repeats it within a rule, never compares equal and is PUT
		// on every reconcile. The response cannot tell what is stored for those
		// ids, so the check stays strict rather than risk missing a real change.
		if !groupIDsEqual(policyrule.Sources, sources) {
			c.log.Info("sources don't match")
			return false
		}
		// PortRanges nil check and comparison
		if policyrule.PortRanges == nil && nbPolicy.Rules[i].PortRanges != nil {
			c.log.Info("port ranges: API nil, spec not nil")
			return false
		}
		if policyrule.PortRanges != nil && nbPolicy.Rules[i].PortRanges == nil {
			c.log.Info("port ranges: API not nil, spec nil")
			return false
		}
		if policyrule.PortRanges != nil && nbPolicy.Rules[i].PortRanges != nil {
			// Compare each start/end pair
			apiRanges := *policyrule.PortRanges
			specRanges := nbPolicy.Rules[i].PortRanges
			if len(apiRanges) != len(*specRanges) {
				c.log.Info("port ranges length doesn't match")
				return false
			}
			for j := range apiRanges {
				if apiRanges[j].Start != (*specRanges)[j].Start || apiRanges[j].End != (*specRanges)[j].End {
					c.log.Info("port range doesn't match", "index", j, "api", apiRanges[j], "spec", (*specRanges)[j])
					return false
				}
			}
		}
		// Ports nil check and comparison
		if policyrule.Ports == nil && nbPolicy.Rules[i].Ports != nil {
			c.log.Info("ports: API nil, spec not nil")
			return false
		}
		if policyrule.Ports != nil && nbPolicy.Rules[i].Ports == nil {
			c.log.Info("ports: API not nil, spec nil")
			return false
		}
		if policyrule.Ports != nil && nbPolicy.Rules[i].Ports != nil {
			if !reflect.DeepEqual(policyrule.Ports, nbPolicy.Rules[i].Ports) {
				c.log.Info("ports don't match")
				return false
			}
		}
	}
	return true
}
func ApiToNBRules(p []nbapi.PolicyRule) *[]v1alpha1.PolicyRule {
	rules := make([]v1alpha1.PolicyRule, len(p))
	for i, prule := range p {
		rules[i] = v1alpha1.PolicyRule{
			Action:        string(prule.Action),
			Bidirectional: prule.Bidirectional,
			Description:   prule.Description,
			Destinations:  ApiToNBGroupMinimums(prule.Destinations),
			Enabled:       prule.Enabled,
			Id:            prule.Id,
			Name:          prule.Name,
			PortRanges:    ApiToNBPortRanges(prule.PortRanges),
			Ports:         prule.Ports,
			Protocol:      string(prule.Protocol),
			Sources:       ApiToNBGroupMinimums(prule.Sources),
		}
	}
	return &rules
}

func ApiToNBPortRanges(rulePortRange *[]nbapi.RulePortRange) *[]v1alpha1.RulePortRange {
	if rulePortRange == nil {
		return nil
	}
	rportrange := make([]v1alpha1.RulePortRange, len(*rulePortRange))
	for i, rulePort := range *rulePortRange {
		rportrange[i] = v1alpha1.RulePortRange{
			End:   rulePort.End,
			Start: rulePort.Start,
		}
	}
	return &rportrange
}

func ApiToNBGroupMinimums(groupMinimum *[]nbapi.GroupMinimum) *[]v1alpha1.GroupMinimum {
	if groupMinimum == nil {
		return nil
	}
	groupminimums := make([]v1alpha1.GroupMinimum, len(*groupMinimum))
	for i, gmin := range *groupMinimum {
		groupminimums[i] = v1alpha1.GroupMinimum{
			Id:             &gmin.Id,
			Name:           &gmin.Name,
			Issued:         (*string)(gmin.Issued),
			PeersCount:     gmin.PeersCount,
			ResourcesCount: gmin.ResourcesCount,
		}
	}
	return &groupminimums
}
