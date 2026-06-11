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

package nbnameserver

import (
	"context"
	"reflect"
	"strings"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"

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
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	nbapi "github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	errNotNbNameServer = "managed resource is not a NbNameServer custom resource"
)

// Setup adds a controller that reconciles NbNameServer managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbNameServerGroupKind)

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
		resource.ManagedKind(v1alpha1.NbNameServerGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbNameServer{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	*auth.SharedConnector
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	_, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return nil, errors.New(errNotNbNameServer)
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
		log:         ctrl.Log.WithName("provider-nbnameserver"),
	}, nil
}

// authClient is the subset of the netbird auth manager used by this controller.
type authClient interface {
	GetClient(ctx context.Context) (*netbird.Client, error)
	ForceRefresh(ctx context.Context) error
}

// external implements managed.ExternalClient for the NbNameServer managed resource.
type external struct {
	authManager authClient
	log         logr.Logger
}

// Observe checks whether the NbNameServer currently exists in netbird and updates status.
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbNameServer)
	}

	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}

	externalName := meta.GetExternalName(cr)
	lookupID := resolveNameServerLookupID(cr)

	// The external-name annotation is not guaranteed to hold a provider ID:
	// it may be empty (fresh MR), the object name (older reconciles), or the
	// netbird display name (composition adoption hint). Try the lookup ID as an
	// ID first, and on not-found fall back to adoption by Name.
	var nameservergroup *nbapi.NameserverGroup
	if lookupID != "" && lookupID != cr.Name && lookupID != cr.Spec.ForProvider.Name {
		nameservergroup, err = client.DNS.GetNameserverGroup(ctx, lookupID)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			if !isNameServerNotFoundError(err) {
				// Don't swallow transient errors — Crossplane should requeue, not call Create.
				return managed.ExternalObservation{}, errors.Wrapf(err, "failed to observe nameserver group %q", lookupID)
			}
			c.log.Info("nameserver group not found by id, attempting adoption by name", "lookup-id", lookupID)
		}
	}
	if nameservergroup == nil {
		groups, err := client.DNS.ListNameserverGroups(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to list nameserver groups for adoption")
		}
		var found *nbapi.NameserverGroup
		for _, g := range groups {
			if g.Name == cr.Spec.ForProvider.Name {
				found = &g
				break
			}
		}
		if found != nil {
			meta.SetExternalName(cr, found.Id)
			// Identity is persisted via status.atProvider.id (external-name set
			// during Observe is not persisted by the runtime), which the lookup
			// resolver prefers on subsequent reconciles.
			cr.Status.AtProvider.Id = found.Id
			return managed.ExternalObservation{
				ResourceExists:   true,
				ResourceUpToDate: false, // force a requeue for a fresh Observe
			}, nil
		}
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	// Repair stale or missing external-name annotations after recovering via status ID.
	if externalName != nameservergroup.Id {
		meta.SetExternalName(cr, nameservergroup.Id)
	}

	cr.Status.AtProvider = v1alpha1.NbNameServerObservation{
		Id:                   nameservergroup.Id,
		Description:          nameservergroup.Description,
		Domains:              nameservergroup.Domains,
		Groups:               nameservergroup.Groups,
		Enabled:              nameservergroup.Enabled,
		Name:                 nameservergroup.Name,
		Nameservers:          *ApitoNbNameServer(nameservergroup.Nameservers),
		Primary:              nameservergroup.Primary,
		SearchDomainsEnabled: nameservergroup.SearchDomainsEnabled,
	}

	cr.Status.SetConditions(xpv1.Available())
	isUpToDate := IsNbNameServerUpToDate(*nameservergroup, *cr, c)

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: isUpToDate,
	}, nil
}

// resolveNameServerLookupID picks the best identifier to use when looking the
// nameserver group up by ID, falling back to the recorded provider ID when the
// external-name annotation is missing or was defaulted to the Kubernetes object
// name by an older reconcile (before WithInitializers disabled the
// NameAsExternalName default).
func resolveNameServerLookupID(cr *v1alpha1.NbNameServer) string {
	externalName := meta.GetExternalName(cr)
	switch {
	case externalName == "":
		return cr.Status.AtProvider.Id
	case cr.Status.AtProvider.Id != "" && cr.Status.AtProvider.Id != externalName &&
		(externalName == cr.GetName() || externalName == cr.Spec.ForProvider.Name):
		// Recover when the external name holds the Kubernetes object name (older
		// reconciles) or the netbird display name (composition adoption hint).
		return cr.Status.AtProvider.Id
	default:
		return externalName
	}
}

// isNameServerNotFoundError matches the "nameserver group: <id> not found"
// message returned by the netbird REST API for a missing nameserver group.
func isNameServerNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "nameserver") && strings.Contains(errStr, "not found")
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbNameServer)
	}

	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}

	nameserverGroup, err := client.DNS.CreateNameserverGroup(ctx, nbapi.PostApiDnsNameserversJSONRequestBody{
		Description:          cr.Spec.ForProvider.Description,
		Domains:              cr.Spec.ForProvider.Domains,
		Groups:               cr.Spec.ForProvider.Groups,
		Enabled:              cr.Spec.ForProvider.Enabled,
		Name:                 cr.Spec.ForProvider.Name,
		Nameservers:          *NbtoApiNameServer(cr.Spec.ForProvider.Nameservers),
		Primary:              cr.Spec.ForProvider.Primary,
		SearchDomainsEnabled: cr.Spec.ForProvider.SearchDomainsEnabled,
	})
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to create nameserver group")
	}

	meta.SetExternalName(cr, nameserverGroup.Id)
	return managed.ExternalCreation{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbNameServer)
	}

	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}

	nsGroupID := resolveNameServerLookupID(cr)
	if nsGroupID == "" {
		return managed.ExternalUpdate{}, errors.New("can't find nameserver group id")
	}
	_, err = client.DNS.UpdateNameserverGroup(ctx, nsGroupID, nbapi.PutApiDnsNameserversNsgroupIdJSONRequestBody{
		Description:          cr.Spec.ForProvider.Description,
		Domains:              cr.Spec.ForProvider.Domains,
		Groups:               cr.Spec.ForProvider.Groups,
		Enabled:              cr.Spec.ForProvider.Enabled,
		Name:                 cr.Spec.ForProvider.Name,
		Nameservers:          *NbtoApiNameServer(cr.Spec.ForProvider.Nameservers),
		Primary:              cr.Spec.ForProvider.Primary,
		SearchDomainsEnabled: cr.Spec.ForProvider.SearchDomainsEnabled,
	})
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to update nameserver group")
	}

	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return errors.New(errNotNbNameServer)
	}

	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}

	nsGroupID := resolveNameServerLookupID(cr)
	if nsGroupID == "" {
		return errors.New("can't find nameserver group id")
	}
	if err := client.DNS.DeleteNameserverGroup(ctx, nsGroupID); err != nil {
		return errors.Wrap(err, "failed to delete nameserver group")
	}

	return nil
}

func ApitoNbNameServer(p []nbapi.Nameserver) *[]v1alpha1.Nameserver {
	nameservers := make([]v1alpha1.Nameserver, len(p))
	for i, ns := range p {
		nameservers[i] = v1alpha1.Nameserver{
			Ip:     ns.Ip,
			Port:   ns.Port,
			NsType: v1alpha1.NameserverNsType(ns.NsType),
		}
	}
	return &nameservers
}

func NbtoApiNameServer(p []v1alpha1.Nameserver) *[]nbapi.Nameserver {
	nameservers := make([]nbapi.Nameserver, len(p))
	for i, ns := range p {
		nameservers[i] = nbapi.Nameserver{
			Ip:     ns.Ip,
			Port:   ns.Port,
			NsType: nbapi.NameserverNsType(ns.NsType),
		}
	}
	return &nameservers
}

func IsNbNameServerUpToDate(p nbapi.NameserverGroup, ns v1alpha1.NbNameServer, c *external) bool {
	if !cmp.Equal(p.Description, ns.Spec.ForProvider.Description) {
		c.log.Info("description doesn't match")
		return false
	}
	if !reflect.DeepEqual(p.Domains, ns.Spec.ForProvider.Domains) {
		c.log.Info("domains don't match")
		return false
	}
	if !cmp.Equal(p.Enabled, ns.Spec.ForProvider.Enabled) {
		c.log.Info("enabled doesn't match")
		return false
	}
	if !reflect.DeepEqual(p.Groups, ns.Spec.ForProvider.Groups) {
		c.log.Info("groups don't match")
		return false
	}
	if !cmp.Equal(p.Name, ns.Spec.ForProvider.Name) {
		c.log.Info("name doesn't match")
		return false
	}
	if !cmp.Equal(len(p.Nameservers), len(ns.Spec.ForProvider.Nameservers)) {
		c.log.Info("nameservers don't match")
		return false
	}
	for i, pns := range p.Nameservers {
		if !cmp.Equal(pns.Ip, ns.Spec.ForProvider.Nameservers[i].Ip) {
			return false
		}
		if !cmp.Equal(string(pns.NsType), string(ns.Spec.ForProvider.Nameservers[i].NsType)) {
			return false
		}
		if !cmp.Equal(pns.Port, ns.Spec.ForProvider.Nameservers[i].Port) {
			return false
		}
	}
	return true
}
