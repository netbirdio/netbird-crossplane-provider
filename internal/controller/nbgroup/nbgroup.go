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

package nbgroup

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/feature"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	apisv1alpha1 "github.com/crossplane/netbird-crossplane-provider/apis/v1alpha1"
	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	auth "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	"github.com/crossplane/netbird-crossplane-provider/internal/features"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	nbapi "github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	errNotNbGroup   = "managed resource is not a NbGroup custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"
)

// Setup adds a controller that reconciles NbGroup managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbGroupGroupKind)

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
		resource.ManagedKind(v1alpha1.NbGroupGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbGroup{}).
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
	_, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return nil, errors.New(errNotNbGroup)
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
		log:         ctrl.Log.WithName("provider-nbgroup"),
	}, nil
}

// authClient is the subset of the netbird auth manager used by this controller.
type authClient interface {
	GetClient(ctx context.Context) (*netbird.Client, error)
	ForceRefresh(ctx context.Context) error
}

// external implements managed.ExternalClient for the NbGroup managed resource.
type external struct {
	authManager authClient
	log         logr.Logger
}

// Observe checks whether the NbGroup currently exists in netbird and updates status.
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {

	cr, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbGroup)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Observing", "cr", cr)
	externalName := meta.GetExternalName(cr)
	lookupID := resolveGroupLookupID(cr)

	// Adoption pattern: if we don't yet have a stable provider ID, try to find by Name.
	if lookupID == "" || lookupID == cr.Name {
		c.log.Info("external name blank or matches resource name, attempting adoption by Name", "name", cr.Spec.ForProvider.Name)
		groups, err := client.Groups.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to list groups for adoption")
		}
		for _, apigroup := range groups {
			if apigroup.Name == cr.Spec.ForProvider.Name {
				c.log.Info("found existing group for adoption", "groupid", apigroup.Id)
				meta.SetExternalName(cr, apigroup.Id)
				cr.Status.SetConditions(xpv1.Available())
				cr.Status.AtProvider = v1alpha1.NbGroupObservation{
					Id:             apigroup.Id,
					Issued:         apigroup.Issued,
					Peers:          apigroup.Peers,
					PeersCount:     apigroup.PeersCount,
					Resources:      apigroup.Resources,
					ResourcesCount: apigroup.ResourcesCount,
				}
				c.log.Info("set atprovider id", "id", cr.Status.AtProvider.Id)
				return managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true, //since we don't update groups
				}, nil
			}
		}
		// Not found, resource does not exist
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	if lookupID == cr.Spec.ForProvider.Name {
		// Only check for existence, do not set external name
		c.log.Info("external name matches ForProvider.Name, checking existence only", "name", cr.Spec.ForProvider.Name)
		groups, err := client.Groups.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to list groups by ForProvider.Name")
		}
		for _, apigroup := range groups {
			if apigroup.Name == lookupID {
				c.log.Info("found existing group by ForProvider.Name", "groupid", apigroup.Id)
				cr.Status.SetConditions(xpv1.Available())
				cr.Status.AtProvider = v1alpha1.NbGroupObservation{
					Id:             apigroup.Id,
					Issued:         apigroup.Issued,
					Peers:          apigroup.Peers,
					PeersCount:     apigroup.PeersCount,
					Resources:      apigroup.Resources,
					ResourcesCount: apigroup.ResourcesCount,
				}
				c.log.Info("set atprovider id", "id", cr.Status.AtProvider.Id)
				return managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true, //since we don't update groups
				}, nil
			}
		}
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	c.log.Info("external name set, fetching by ID", "lookupID", lookupID)
	apigroup, err := client.Groups.Get(ctx, lookupID)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		if isGroupNotFoundError(err) {
			c.log.Info("group not found", "lookup-id", lookupID)
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil
		}
		// Don't swallow transient errors — Crossplane should requeue, not call Create.
		return managed.ExternalObservation{}, errors.Wrapf(err, "failed to observe group %q", lookupID)
	}
	group := *apigroup

	// Repair stale or missing external-name annotations after recovering via status ID.
	if externalName != group.Id {
		meta.SetExternalName(cr, group.Id)
	}

	cr.Status.SetConditions(xpv1.Available())
	c.log.Info("setting atprovider")
	cr.Status.AtProvider = v1alpha1.NbGroupObservation{
		Id:             group.Id,
		Issued:         group.Issued,
		Peers:          group.Peers,
		PeersCount:     group.PeersCount,
		Resources:      group.Resources,
		ResourcesCount: group.ResourcesCount,
	}
	c.log.Info("set atprovider id", "id", cr.Status.AtProvider.Id)
	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true, //since we don't update groups
	}, nil
}

// resolveGroupLookupID picks the best identifier to use when looking the group
// up by ID, falling back to the recorded provider ID when the external-name
// annotation is missing or was defaulted to the Kubernetes object name by an
// older reconcile (before WithInitializers disabled the NameAsExternalName default).
func resolveGroupLookupID(cr *v1alpha1.NbGroup) string {
	externalName := meta.GetExternalName(cr)
	switch {
	case externalName == "":
		return cr.Status.AtProvider.Id
	case cr.Status.AtProvider.Id != "" && externalName == cr.GetName() && cr.Status.AtProvider.Id != externalName:
		// Recover from older reconciles that defaulted the external name to the Kubernetes object name.
		return cr.Status.AtProvider.Id
	default:
		return externalName
	}
}

// isGroupNotFoundError matches the "group: <id> not found" message returned
// by the netbird REST API for a missing group. Does not match the
// "nameserver group: <id> not found" form because Groups.Get is a different
// endpoint and never returns that string.
func isGroupNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "group") && strings.Contains(errStr, "not found")
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbGroup)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Creating", "cr", cr)
	group, err := client.Groups.Create(ctx, nbapi.GroupRequest{
		Name: cr.Spec.ForProvider.Name,
	})

	if err != nil {
		return managed.ExternalCreation{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
	c.log.Info("group created", "group", group)
	meta.SetExternalName(cr, group.Id)
	return managed.ExternalCreation{}, nil
}

// we don't update group
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbGroup)
	}
	c.log.Info("Updating", "cr", cr) //no fields update on group
	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return errors.New(errNotNbGroup)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Deleting", "cr", cr)
	groupid := resolveGroupLookupID(cr)
	if groupid == "" {
		return errors.New("can't find group id")
	}
	return client.Groups.Delete(ctx, groupid)
}
