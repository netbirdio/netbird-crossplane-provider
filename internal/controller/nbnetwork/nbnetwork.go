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
	netbird "github.com/netbirdio/netbird/management/client/rest"
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	errNotNbNetwork = "managed resource is not a NbNetwork custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"
)

// Setup adds a controller that reconciles NbNetwork managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbNetworkGroupKind)

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
		resource.ManagedKind(v1alpha1.NbNetworkGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbNetwork{}).
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
	_, ok := mg.(*v1alpha1.NbNetwork)
	if !ok {
		return nil, errors.New(errNotNbNetwork)
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
		log:         ctrl.Log.WithName("provider-nbnetwork"),
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
	cr, ok := mg.(*v1alpha1.NbNetwork)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbNetwork)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("observing", "cr", cr)
	externalName := meta.GetExternalName(cr)
	lookupID := resolveNetworkLookupID(cr)

	// Adoption pattern: if we don't yet have a stable provider ID, try to find by Name.
	// lookupID == "" covers a fresh resource with no external name and no status ID.
	// lookupID == cr.Name covers older reconciles that defaulted external-name to the k8s
	// object name without ever recording a real status ID.
	if lookupID == "" || lookupID == cr.Name {
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
		for _, net := range networks {
			if net.Name == cr.Spec.ForProvider.Name {
				meta.SetExternalName(cr, net.Id)
				cr.Status.AtProvider = v1alpha1.NbNetworkObservation{
					Id:                net.Id,
					Resources:         &net.Resources,
					Description:       net.Description,
					Name:              net.Name,
					Policies:          &net.Policies,
					Routers:           &net.Routers,
					RoutingPeersCount: net.RoutingPeersCount,
				}
				cr.Status.SetConditions(xpv1.Available())
				return managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: false, // force requeue to persist external name
				}, nil
			}
		}
		// Not found by name, treat as not existing
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	// If we have a resolved lookup ID, fetch by ID.
	network, err := client.Networks.Get(ctx, lookupID)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		if isNetworkNotFoundError(err) {
			c.log.Info("network not found", "lookup-id", lookupID)
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil
		}
		// Don't swallow transient errors — Crossplane should requeue, not call Create.
		return managed.ExternalObservation{}, errors.Wrapf(err, "failed to observe network %q", lookupID)
	}

	// Repair stale or missing external-name annotations after recovering via status ID.
	if externalName != network.Id {
		meta.SetExternalName(cr, network.Id)
	}

	cr.Status.AtProvider = v1alpha1.NbNetworkObservation{
		Id:                network.Id,
		Resources:         &network.Resources,
		Description:       network.Description,
		Name:              network.Name,
		Policies:          &network.Policies,
		Routers:           &network.Routers,
		RoutingPeersCount: network.RoutingPeersCount,
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: isnetworkuptodate(network, cr.Spec.ForProvider),
	}, nil
}

// resolveNetworkLookupID picks the best identifier to use when looking the network
// up by ID, falling back to the recorded provider ID when the external-name
// annotation is missing or was defaulted to the Kubernetes object name by an
// older reconcile (before WithInitializers disabled the NameAsExternalName default).
func resolveNetworkLookupID(cr *v1alpha1.NbNetwork) string {
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

// isNetworkNotFoundError matches the "network: <id> not found" message
// returned by the netbird REST API for a missing network.
func isNetworkNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "network") && strings.Contains(errStr, "not found")
}

func isnetworkuptodate(network *nbapi.Network, nbNetworkParameters v1alpha1.NbNetworkParameters) bool {
	if !cmp.Equal(*network.Description, nbNetworkParameters.Description) {
		return false
	}
	if !cmp.Equal(network.Name, nbNetworkParameters.Name) {
		return false
	}
	return true
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbNetwork)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbNetwork)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("creating", "cr", cr)
	network, err := client.Networks.Create(ctx, nbapi.NetworkRequest{
		Name:        cr.Spec.ForProvider.Name,
		Description: &cr.Spec.ForProvider.Description,
	})

	if err != nil {
		return managed.ExternalCreation{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
	meta.SetExternalName(cr, network.Id)
	return managed.ExternalCreation{}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbNetwork)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbNetwork)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}
	networkid := resolveNetworkLookupID(cr)
	if networkid == "" {
		return managed.ExternalUpdate{}, errors.New("can't find network id")
	}
	c.log.Info("Updating", "cr", cr)
	_, err = client.Networks.Update(ctx, networkid, nbapi.PutApiNetworksNetworkIdJSONRequestBody{
		Name:        cr.Spec.ForProvider.Name,
		Description: &cr.Spec.ForProvider.Description,
	})
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbNetwork)
	if !ok {
		return errors.New(errNotNbNetwork)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Deleting", "cr", cr)
	networkid := resolveNetworkLookupID(cr)
	if networkid == "" {
		return errors.New("can't find network id")
	}
	return client.Networks.Delete(ctx, networkid)
}
