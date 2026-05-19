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
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	errNotNbNetworkResource = "managed resource is not a NbNetworkResource custom resource"
	errTrackPCUsage         = "cannot track ProviderConfig usage"
	errGetPC                = "cannot get ProviderConfig"
	errGetCreds             = "cannot get credentials"
)

// Setup adds a controller that reconciles NbNetworkResource managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbNetworkResourceGroupKind)

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
	}
	if o.Features.Enabled(feature.EnableBetaManagementPolicies) {
		reconcilerOptions = append(reconcilerOptions, managed.WithManagementPolicies())
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.NbNetworkResourceGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbNetworkResource{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	*auth.SharedConnector
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	_, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return nil, errors.New(errNotNbNetworkResource)
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
		log:         ctrl.Log.WithName("provider-nbnetworkresource"),
	}, nil
}

type external struct {
	authManager *auth.AuthManager
	log         logr.Logger
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbNetworkResource)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("observing", "cr", cr)
	externalName := meta.GetExternalName(cr)

	// Adoption pattern: if externalName is blank or matches resource name, try to find by Name
	if externalName == "" || externalName == cr.Name {
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
			return managed.ExternalObservation{ResourceExists: false}, errors.New("network name not found")
		}
		resources, err := client.Networks.Resources(apinetwork.Id).List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			c.log.Info("failed to list network resources")
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil //return nil so that observe can return without error so that it passes to create.
		}
		for _, res := range resources {
			if res.Name == cr.Spec.ForProvider.Name {
				meta.SetExternalName(cr, res.Id)
				cr.Status.AtProvider = v1alpha1.NbNetworkResourceObservation{
					Id:          res.Id,
					Enabled:     res.Enabled,
					Address:     res.Address,
					Description: res.Description,
					Groups:      convertGroups(res.Groups),
					Name:        res.Name,
					Type:        string(res.Type),
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
		return managed.ExternalObservation{ResourceExists: false}, errors.New("network name not found")
	}
	networkresource, err := client.Networks.Resources(apinetwork.Id).Get(ctx, externalName)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		c.log.Info("failed to get network resource")
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil //return nil so that observe can return without error so that it passes to create.
	}
	cr.Status.AtProvider = v1alpha1.NbNetworkResourceObservation{
		Id:          networkresource.Id,
		Enabled:     networkresource.Enabled,
		Address:     networkresource.Address,
		Description: networkresource.Description,
		Groups:      convertGroups(networkresource.Groups),
		Name:        networkresource.Name,
		Type:        string(networkresource.Type),
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true, // TODO: implement up-to-date check if needed
	}, nil
}

// resolveGroupIDs translates the user-supplied group references on the
// NbNetworkResource spec into the API-side group ids the netbird mgmt
// API expects.
//
// Each spec entry can identify a group by Id (preferred — stable, set
// directly by the user or by another Crossplane MR) or by Name (a
// human-readable fallback resolved against the account's current group
// list). Either pointer may be nil.
//
// Previously this loop unconditionally deref'd `*provgroup.Name`, which
// panicked whenever the spec omitted Name (a common case — Id is the
// canonical reference and Name is optional in the schema).
func resolveGroupIDs(provgroups []v1alpha1.GroupMinimum, apigroups []nbapi.Group) ([]string, error) {
	out := make([]string, 0, len(provgroups))
	for _, provgroup := range provgroups {
		// Prefer the explicit Id if supplied — no API lookup needed.
		if provgroup.Id != nil && *provgroup.Id != "" {
			out = append(out, *provgroup.Id)
			continue
		}
		// Fall back to name lookup.
		if provgroup.Name == nil || *provgroup.Name == "" {
			return nil, errors.New("group reference missing both id and name")
		}
		var matched bool
		for _, apigroup := range apigroups {
			if apigroup.Name == *provgroup.Name {
				out = append(out, apigroup.Id)
				matched = true
				break
			}
		}
		if !matched {
			return nil, errors.Errorf("group not found by name: %q", *provgroup.Name)
		}
	}
	return out, nil
}

func convertGroups(groupMinimums []nbapi.GroupMinimum) *[]v1alpha1.GroupMinimum {
	groups := make([]v1alpha1.GroupMinimum, len(groupMinimums))
	for i, g := range groupMinimums {
		groups[i] = v1alpha1.GroupMinimum{
			Id: &g.Id,
			//Issued:         &g.Issued,
			Name:           &g.Name,
			PeersCount:     g.PeersCount,
			ResourcesCount: g.ResourcesCount,
		}
	}
	return &groups
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbNetworkResource)
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
		return managed.ExternalCreation{}, errors.New("network name not found")
	}
	groups, err := client.Groups.List(ctx)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	groupids, err := resolveGroupIDs(*cr.Spec.ForProvider.Groups, groups)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	networkresource, err := client.Networks.Resources(apinetwork.Id).Create(ctx, nbapi.NetworkResourceRequest{
		Enabled:     cr.Spec.ForProvider.Enabled,
		Address:     cr.Spec.ForProvider.Address,
		Description: cr.Spec.ForProvider.Description,
		Groups:      groupids,
		Name:        cr.Spec.ForProvider.Name,
	})

	if err != nil {
		return managed.ExternalCreation{}, err
	}
	meta.SetExternalName(cr, networkresource.Id)
	return managed.ExternalCreation{}, nil
}

// func convertGMToStringArray(groupids []string) []string {
// 	groups := make([]string, len(groupMinimum))
// 	for i, g := range groupMinimum {
// 		groups[i] = g.Id
// 	}
// 	return groups
// }

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbNetworkResource)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}
	networkResourceId := meta.GetExternalName(cr)
	c.log.Info("Updating", "cr", cr)
	networks, err := client.Networks.List(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	var apinetwork *nbapi.Network
	for _, network := range networks {
		if network.Name == cr.Spec.ForProvider.NetworkName {
			apinetwork = &network
		}
	}
	if apinetwork == nil {
		return managed.ExternalUpdate{}, errors.New("network name not found")
	}
	groups, err := client.Groups.List(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	groupids, err := resolveGroupIDs(*cr.Spec.ForProvider.Groups, groups)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	_, err2 := client.Networks.Resources(apinetwork.Id).Update(ctx, networkResourceId, nbapi.PutApiNetworksNetworkIdResourcesResourceIdJSONRequestBody{
		Enabled:     cr.Spec.ForProvider.Enabled,
		Address:     cr.Spec.ForProvider.Address,
		Description: cr.Spec.ForProvider.Description,
		Groups:      groupids,
		Name:        cr.Spec.ForProvider.Name,
	})
	if err2 != nil {
		return managed.ExternalUpdate{}, err
	}

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return errors.New(errNotNbNetworkResource)
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
	networkresourceid := meta.GetExternalName(cr)
	return client.Networks.Resources(apinetwork.Id).Delete(ctx, networkresourceid)
}
