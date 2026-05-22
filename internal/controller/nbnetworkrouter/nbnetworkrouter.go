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
	netbird "github.com/netbirdio/netbird/management/client/rest"
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
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

type external struct {
	authManager authClient
	log         logr.Logger
}

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

	// Adoption pattern: if we don't yet have a stable provider ID, try to find by PeerGroupName or Peer.
	// lookupID == "" covers a fresh resource with no external name and no status ID.
	// lookupID == cr.Name covers older reconciles that defaulted external-name to the k8s
	// object name without ever recording a real status ID.
	if lookupID == "" || lookupID == cr.Name {
		c.log.Info("external name blank or matches resource name, attempting adoption by PeerGroupName or Peer")
		networks, err := client.Networks.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			c.log.Info("failed to list networks")
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil //return nil so that observe can return without error so that it passes to create.
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
		routers, err := client.Networks.Routers(apinetwork.Id).List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			c.log.Info("failed to list routers")
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil //return nil so that observe can return without error so that it passes to create.
		}
		for _, router := range routers {
			if cr.Spec.ForProvider.PeerGroupName != "" {
				if router.PeerGroups != nil && len(*router.PeerGroups) > 0 {
					// Find the group ID for the PeerGroupName
					groups, err := client.Groups.List(ctx)
					if err != nil {
						c.log.Error(err, "failed to list groups for adoption")
						continue
					}
					var groupID string
					for _, g := range groups {
						if g.Name == cr.Spec.ForProvider.PeerGroupName {
							groupID = g.Id
							break
						}
					}
					if groupID == "" {
						c.log.Info("PeerGroupName not found in Netbird groups", "PeerGroupName", cr.Spec.ForProvider.PeerGroupName)
						continue
					}
					c.log.Info("external name blank or matches resource name, attempting adoption by PeerGroupName")
					cr.Status.AtProvider = v1alpha1.NbNetworkRouterObservation{
						Id:         router.Id,
						Enabled:    router.Enabled,
						Masquerade: router.Masquerade,
						Metric:     router.Metric,
						PeerGroup:  &groupID,
						Peer:       nil,
					}
					cr.Status.SetConditions(xpv1.Available())
					meta.SetExternalName(cr, router.Id)
					return managed.ExternalObservation{
						ResourceExists:   true,
						ResourceUpToDate: false, // force requeue to persist external name
					}, nil
				}
				continue
			}
			if cr.Spec.ForProvider.PeerGroupName == "" && cr.Spec.ForProvider.Peer != nil && router.Peer != nil && *router.Peer == *cr.Spec.ForProvider.Peer {
				c.log.Info("external name blank or matches resource name, attempting adoption by Peer ID")
				cr.Status.AtProvider = v1alpha1.NbNetworkRouterObservation{
					Id:         router.Id,
					Enabled:    router.Enabled,
					Masquerade: router.Masquerade,
					Metric:     router.Metric,
					PeerGroup:  nil,
					Peer:       router.Peer,
				}
				cr.Status.SetConditions(xpv1.Available())
				meta.SetExternalName(cr, router.Id)
				return managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: false, // force requeue to persist external name
				}, nil
			}
		}
		// Not found by group or peer, treat as not existing
		c.log.Info("external name blank or matches resource name, couldn't find by PeerGroupName or Peer")
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	// If we have an external name (and it's not just the resource name), fetch by ID
	networks, err := client.Networks.List(ctx)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		c.log.Info("failed to list networks")
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil //return nil so that observe can return without error so that it passes to create.
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
	networkrouter, err := client.Networks.Routers(apinetwork.Id).Get(ctx, lookupID)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		if isNetworkRouterNotFoundError(err) {
			c.log.Info("network router not found", "lookup-id", lookupID)
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil
		}
		// Don't swallow transient errors — Crossplane should requeue, not call Create.
		return managed.ExternalObservation{}, errors.Wrapf(err, "failed to observe network router %q", lookupID)
	}

	// Repair stale or missing external-name annotations after recovering via status ID.
	if externalName != networkrouter.Id {
		meta.SetExternalName(cr, networkrouter.Id)
	}

	if networkrouter.PeerGroups != nil && len(*networkrouter.PeerGroups) >= 1 {
		cr.Status.AtProvider = v1alpha1.NbNetworkRouterObservation{
			Id:         networkrouter.Id,
			Enabled:    networkrouter.Enabled,
			Masquerade: networkrouter.Masquerade,
			Metric:     networkrouter.Metric,
			PeerGroup:  &(*networkrouter.PeerGroups)[0],
			Peer:       nil,
		}
	} else {
		cr.Status.AtProvider = v1alpha1.NbNetworkRouterObservation{
			Id:         networkrouter.Id,
			Enabled:    networkrouter.Enabled,
			Masquerade: networkrouter.Masquerade,
			Metric:     networkrouter.Metric,
			PeerGroup:  nil,
			Peer:       networkrouter.Peer,
		}
	}
	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true, // TODO: implement up-to-date check if needed
	}, nil
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

	groups, err := client.Groups.List(ctx)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	groupids := make([]string, 1)

	for _, apigroup := range groups {
		if apigroup.Name == cr.Spec.ForProvider.PeerGroupName {
			groupids[0] = apigroup.Id
			break
		}
	}
	if groupids[0] == "" {
		return managed.ExternalCreation{}, errors.New("group not found")
	}

	networkrouter, err := client.Networks.Routers(apinetwork.Id).Create(ctx, nbapi.NetworkRouterRequest{
		Enabled:    cr.Spec.ForProvider.Enabled,
		Masquerade: cr.Spec.ForProvider.Masquerade,
		Metric:     cr.Spec.ForProvider.Metric,
		Peer:       cr.Spec.ForProvider.Peer,
		PeerGroups: &groupids,
	})

	if err != nil {
		return managed.ExternalCreation{}, err
	}
	meta.SetExternalName(cr, networkrouter.Id)
	return managed.ExternalCreation{}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkRouter)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbNetworkRouter)
	}
	// client, err := c.authManager.GetClient(ctx)
	// if err != nil {
	// 	return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	// }
	//networkid := meta.GetExternalName(cr)
	c.log.Info("Updating", "cr", cr)
	//todo
	// if err != nil {
	// 	return managed.ExternalUpdate{}, err
	// }

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

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
