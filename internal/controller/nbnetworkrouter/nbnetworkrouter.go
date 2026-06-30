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
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	nbapi "github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	errNotNbNetworkRouter = "managed resource is not a NbNetworkRouter custom resource"
	errTrackPCUsage       = "cannot track ProviderConfig usage"
	errGetPC              = "cannot get ProviderConfig"
	errGetCreds           = "cannot get credentials"
)

// Setup adds a controller that reconciles NbNetworkRouter managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbNetworkRouterGroupKind)

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
		resource.ManagedKind(v1alpha1.NbNetworkRouterGroupVersionKind),
		reconcilerOptions...,
	)
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbNetworkRouter{}).
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
	_, ok := mg.(*v1alpha1.NbNetworkRouter)
	if !ok {
		return nil, errors.New(errNotNbNetworkRouter)
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
		log:         ctrl.Log.WithName("provider-nbnetworkrouter"),
	}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type authClient interface {
	GetClient(ctx context.Context) (*netbird.Client, error)
	ForceRefresh(ctx context.Context) error
}

// external implements managed.ExternalClient for the NbNetworkRouter managed resource.
type external struct {
	authManager authClient
	log         logr.Logger
}

// Observe checks whether the NbNetworkRouter currently exists in netbird and updates status.
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkRouter)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbNetworkRouter)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("observing", "cr", cr)
	externalName := meta.GetExternalName(cr)
	lookupID := resolveNetworkRouterLookupID(cr)

	networks, err := client.Networks.List(ctx)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		// Don't swallow transient errors — Crossplane should requeue, not call Create.
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to list networks")
	}
	var apinetwork *nbapi.Network
	for _, network := range networks {
		if network.Name == cr.Spec.ForProvider.NetworkName {
			apinetwork = &network
			break
		}
	}
	if apinetwork == nil {
		return managed.ExternalObservation{}, errors.New("network not found")
	}

	// The external-name annotation is not guaranteed to hold a provider ID (older
	// reconciles defaulted it to the object name, or it may hold a display name set
	// as an adoption hint). Try the lookup ID as an ID first, and on not-found fall
	// back to adoption by PeerGroupName or Peer within the parent network.
	if lookupID != "" && lookupID != cr.Name {
		networkrouter, err := client.Networks.Routers(apinetwork.Id).Get(ctx, lookupID)
		switch {
		case err == nil:
			// Repair stale or missing external-name annotations after recovering via status ID.
			if externalName != networkrouter.Id {
				meta.SetExternalName(cr, networkrouter.Id)
			}
			cr.Status.AtProvider = networkRouterObservation(networkrouter)
			cr.Status.SetConditions(xpv1.Available())
			uptodate, err := c.isNetworkRouterUpToDate(ctx, client, cr.Spec.ForProvider, networkrouter)
			if err != nil {
				return managed.ExternalObservation{}, err
			}
			return managed.ExternalObservation{
				ResourceExists:   true,
				ResourceUpToDate: uptodate,
			}, nil
		case auth.IsTokenInvalidError(err):
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		case !isNetworkRouterNotFoundError(err):
			// Don't swallow transient errors — Crossplane should requeue, not call Create.
			return managed.ExternalObservation{}, errors.Wrapf(err, "failed to observe network router %q", lookupID)
		}
		c.log.Info("network router not found by id, attempting adoption by PeerGroupName or Peer", "lookup-id", lookupID)
	}

	// Adoption by PeerGroupName or Peer: the netbird router may exist even though we
	// hold no usable ID (fresh MR, or a Create whose external-name persist failed).
	routers, err := client.Networks.Routers(apinetwork.Id).List(ctx)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		// Don't swallow transient errors — a failed list must not look like "doesn't exist".
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to list network routers for adoption")
	}
	var groupID string
	if cr.Spec.ForProvider.PeerGroupName != "" {
		groups, err := client.Groups.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to list groups for adoption")
		}
		for _, g := range groups {
			if g.Name == cr.Spec.ForProvider.PeerGroupName {
				groupID = g.Id
				break
			}
		}
		if groupID == "" {
			c.log.Info("PeerGroupName not found in Netbird groups", "PeerGroupName", cr.Spec.ForProvider.PeerGroupName)
			return managed.ExternalObservation{ResourceExists: false}, nil
		}
	}
	for _, router := range routers {
		matched := false
		if groupID != "" {
			if router.PeerGroups != nil {
				for _, pg := range *router.PeerGroups {
					if pg == groupID {
						matched = true
						break
					}
				}
			}
		} else if cr.Spec.ForProvider.Peer != nil && router.Peer != nil && *router.Peer == *cr.Spec.ForProvider.Peer {
			matched = true
		}
		if matched {
			c.log.Info("adopting existing network router", "router-id", router.Id)
			cr.Status.AtProvider = networkRouterObservation(&router)
			cr.Status.SetConditions(xpv1.Available())
			meta.SetExternalName(cr, router.Id)
			return managed.ExternalObservation{
				ResourceExists:   true,
				ResourceUpToDate: false, // force requeue to persist external name
			}, nil
		}
	}
	// Not found by group or peer, treat as not existing
	c.log.Info("couldn't find network router by PeerGroupName or Peer")
	return managed.ExternalObservation{ResourceExists: false}, nil
}

// networkRouterObservation maps an API network router into the CR's observed state.
func networkRouterObservation(router *nbapi.NetworkRouter) v1alpha1.NbNetworkRouterObservation {
	if router.PeerGroups != nil && len(*router.PeerGroups) >= 1 {
		return v1alpha1.NbNetworkRouterObservation{
			Id:         router.Id,
			Enabled:    router.Enabled,
			Masquerade: router.Masquerade,
			Metric:     router.Metric,
			PeerGroup:  &(*router.PeerGroups)[0],
			Peer:       nil,
		}
	}
	return v1alpha1.NbNetworkRouterObservation{
		Id:         router.Id,
		Enabled:    router.Enabled,
		Masquerade: router.Masquerade,
		Metric:     router.Metric,
		PeerGroup:  nil,
		Peer:       router.Peer,
	}
}

// isNetworkRouterUpToDate compares the desired spec against the observed API
// router so in-place changes (enabled, masquerade, metric, peer re-point) drive
// Update instead of being silently ignored.
func (c *external) isNetworkRouterUpToDate(ctx context.Context, client *netbird.Client, spec v1alpha1.NbNetworkRouterParameters, router *nbapi.NetworkRouter) (bool, error) {
	if spec.Enabled != router.Enabled || spec.Masquerade != router.Masquerade || spec.Metric != router.Metric {
		return false, nil
	}
	if spec.PeerGroupName != "" {
		groups, err := client.Groups.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
			}
			return false, errors.Wrap(err, "failed to list groups for up-to-date check")
		}
		var groupID string
		for _, g := range groups {
			if g.Name == spec.PeerGroupName {
				groupID = g.Id
				break
			}
		}
		if groupID == "" {
			return false, nil
		}
		if router.PeerGroups == nil || len(*router.PeerGroups) != 1 || (*router.PeerGroups)[0] != groupID {
			return false, nil
		}
		return router.Peer == nil || *router.Peer == "", nil
	}
	if spec.Peer != nil {
		return router.Peer != nil && *router.Peer == *spec.Peer, nil
	}
	return true, nil
}

// resolveNetworkRouterLookupID picks the best identifier to use when looking the
// network router up by ID, falling back to the recorded provider ID when the
// external-name annotation is missing or was defaulted to the Kubernetes object
// name by an older reconcile (before WithInitializers disabled the
// NameAsExternalName default).
func resolveNetworkRouterLookupID(cr *v1alpha1.NbNetworkRouter) string {
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

// isNetworkRouterNotFoundError matches the "router: <id> not found" / "network router: <id> not found"
// messages returned by the netbird REST API for a missing network router.
func isNetworkRouterNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "router") && strings.Contains(errStr, "not found")
}

// Create provisions a new netbird network router for the managed resource.
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkRouter)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbNetworkRouter)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("creating", "cr", cr)
	networks, err := client.Networks.List(ctx)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	var apinetwork *nbapi.Network
	for _, network := range networks {
		if network.Name == cr.Spec.ForProvider.NetworkName {
			apinetwork = &network
		}
	}
	if apinetwork == nil {
		return managed.ExternalCreation{}, errors.New("network not found")
	}

	peerGroups, err := c.resolvePeerGroups(ctx, client, cr.Spec.ForProvider)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	networkrouter, err := client.Networks.Routers(apinetwork.Id).Create(ctx, nbapi.NetworkRouterRequest{
		Enabled:    cr.Spec.ForProvider.Enabled,
		Masquerade: cr.Spec.ForProvider.Masquerade,
		Metric:     cr.Spec.ForProvider.Metric,
		Peer:       cr.Spec.ForProvider.Peer,
		PeerGroups: peerGroups,
	})

	if err != nil {
		return managed.ExternalCreation{}, err
	}
	meta.SetExternalName(cr, networkrouter.Id)
	return managed.ExternalCreation{}, nil
}

// resolvePeerGroups translates the spec's PeerGroupName into the API-side group id
// list, or nil for a peer-identified router (peer and peer_groups are mutually
// exclusive in the netbird API).
func (c *external) resolvePeerGroups(ctx context.Context, client *netbird.Client, spec v1alpha1.NbNetworkRouterParameters) (*[]string, error) {
	if spec.PeerGroupName == "" {
		return nil, nil
	}
	groups, err := client.Groups.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, apigroup := range groups {
		if apigroup.Name == spec.PeerGroupName {
			return &[]string{apigroup.Id}, nil
		}
	}
	return nil, errors.Errorf("group not found by name: %q", spec.PeerGroupName)
}

// Update applies the desired spec to the existing netbird network router.
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkRouter)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbNetworkRouter)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Updating", "cr", cr)
	networkrouterid := resolveNetworkRouterLookupID(cr)
	if networkrouterid == "" {
		return managed.ExternalUpdate{}, errors.New("can't find network router id")
	}
	networks, err := client.Networks.List(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	var apinetwork *nbapi.Network
	for _, network := range networks {
		if network.Name == cr.Spec.ForProvider.NetworkName {
			apinetwork = &network
			break
		}
	}
	if apinetwork == nil {
		return managed.ExternalUpdate{}, errors.New("network not found")
	}
	peerGroups, err := c.resolvePeerGroups(ctx, client, cr.Spec.ForProvider)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	_, err = client.Networks.Routers(apinetwork.Id).Update(ctx, networkrouterid, nbapi.NetworkRouterRequest{
		Enabled:    cr.Spec.ForProvider.Enabled,
		Masquerade: cr.Spec.ForProvider.Masquerade,
		Metric:     cr.Spec.ForProvider.Metric,
		Peer:       cr.Spec.ForProvider.Peer,
		PeerGroups: peerGroups,
	})
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrapf(err, "failed to update network router %q", networkrouterid)
	}
	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// Delete removes the netbird network router associated with this managed resource.
func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbNetworkRouter)
	if !ok {
		return errors.New(errNotNbNetworkRouter)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Deleting", "cr", cr)
	networks, err := client.Networks.List(ctx)
	if err != nil {
		return err
	}
	var apinetwork *nbapi.Network
	for _, network := range networks {
		if network.Name == cr.Spec.ForProvider.NetworkName {
			apinetwork = &network
		}
	}
	if apinetwork == nil {
		return errors.New("network not found")
	}
	networkrouterid := resolveNetworkRouterLookupID(cr)
	if networkrouterid == "" {
		return errors.New("can't find network router id")
	}
	return client.Networks.Routers(apinetwork.Id).Delete(ctx, networkrouterid)
}
