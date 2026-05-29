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

package nbsetupkey

import (
	"context"
	"strings"
	"time"

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
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	errNotNbSetupKey = "managed resource is not a NbSetupKey custom resource"
	errTrackPCUsage  = "cannot track ProviderConfig usage"
	errGetPC         = "cannot get ProviderConfig"
	errGetCreds      = "cannot get credentials"
)

// Setup adds a controller that reconciles NbSetupKey managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbSetupKeyGroupKind)

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
		resource.ManagedKind(v1alpha1.NbSetupKeyGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbSetupKey{}).
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
	_, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return nil, errors.New(errNotNbSetupKey)
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
		log:         ctrl.Log.WithName("provider-nbsetupkey"),
	}, nil
}

// authClient is the subset of the netbird auth manager used by this controller.
type authClient interface {
	GetClient(ctx context.Context) (*netbird.Client, error)
	ForceRefresh(ctx context.Context) error
}

// external implements managed.ExternalClient for the NbSetupKey managed resource.
type external struct {
	authManager authClient
	log         logr.Logger
}

// Observe checks whether the NbSetupKey currently exists in netbird and updates status.
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbSetupKey)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Observing", "cr", cr)
	externalName := meta.GetExternalName(cr)
	lookupID := resolveSetupKeyLookupID(cr)

	if lookupID == "" {
		// Update clears both external-name and status.AtProvider.Id when rotating a
		// revoked/expired setup key; observing after that should drive Crossplane
		// to call Create (mint new key) rather than fail.
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	setupkey, err := client.SetupKeys.Get(ctx, lookupID)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		if isSetupKeyNotFoundError(err) {
			c.log.Info("setup key not found", "lookup-id", lookupID)
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil
		}
		// Don't swallow transient errors — Crossplane should requeue, not mint a duplicate key.
		return managed.ExternalObservation{}, errors.Wrapf(err, "failed to observe setup key %q", lookupID)
	}

	// Repair stale or missing external-name annotations after recovering via status ID.
	if externalName != setupkey.Id {
		meta.SetExternalName(cr, setupkey.Id)
	}

	if setupkey.Expires.Before(time.Now()) || setupkey.Revoked {
		// Token setupkey exists but is expired or revoked: trigger Update, not Create
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}
	cr.Status.AtProvider = v1alpha1.NbSetupKeyObservation{
		Id:                  setupkey.Id,
		AllowExtraDnsLabels: setupkey.AllowExtraDnsLabels,
		AutoGroups:          &setupkey.AutoGroups,
		Ephemeral:           setupkey.Ephemeral,
		Expires:             setupkey.Expires.String(),
		LastUsed:            setupkey.LastUsed.String(),
		Name:                setupkey.Name,
		Revoked:             setupkey.Revoked,
		State:               setupkey.State,
		Type:                setupkey.Type,
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  true,
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// resolveSetupKeyLookupID picks the best identifier to use when looking the setup
// key up by ID, falling back to the recorded provider ID when the external-name
// annotation is missing or was defaulted to the Kubernetes object name by an
// older reconcile (before WithInitializers disabled the NameAsExternalName default).
func resolveSetupKeyLookupID(cr *v1alpha1.NbSetupKey) string {
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

// isSetupKeyNotFoundError matches the "setup key: <id> not found" message
// returned by the netbird REST API for a missing setup key.
func isSetupKeyNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "setup key") && strings.Contains(errStr, "not found")
}

// func isUpToDate(nbSetupKeyParameters *v1alpha1.NbSetupKeyParameters, setupkey *api.SetupKey, log logr.Logger) bool {

// 	if !reflect.DeepEqual(nbSetupKeyParameters.AutoGroups, setupkey.AutoGroups) {
// 		log.Info("update failed on auto groups")
// 		return false
// 	}
// 	if !cmp.Equal(nbSetupKeyParameters.Revoked, setupkey.Revoked) {
// 		log.Info("update failed on revoked")
// 		return false
// 	}
// 	return true
// }

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbSetupKey)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Creating", "cr", cr)
	setupkey, err := client.SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:                cr.Spec.ForProvider.Name,
		AllowExtraDnsLabels: &cr.Spec.ForProvider.AllowExtraDnsLabels,
		AutoGroups:          cr.Spec.ForProvider.AutoGroups,
		Ephemeral:           &cr.Spec.ForProvider.Ephemeral,
		ExpiresIn:           cr.Spec.ForProvider.ExpiresIn,
		Type:                cr.Spec.ForProvider.Type,
		UsageLimit:          cr.Spec.ForProvider.UsageLimit,
	})

	if err != nil {
		return managed.ExternalCreation{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
	meta.SetExternalName(cr, setupkey.Id)
	cd := managed.ConnectionDetails{xpv1.ResourceCredentialsSecretPasswordKey: []byte(setupkey.Key)}
	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: cd,
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbSetupKey)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Updating", "cr", cr)
	setupKeyId := resolveSetupKeyLookupID(cr)
	if setupKeyId == "" {
		return managed.ExternalUpdate{}, errors.New("can't find setupKeyId")
	}
	if err := client.SetupKeys.Delete(ctx, setupKeyId); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to delete expired setupkey")
	}
	// Clear both external-name and the recorded provider ID so the next Observe
	// resolves to "" and drives Create — without clearing status, the resolver
	// would fall back to a now-deleted ID.
	meta.SetExternalName(cr, "")
	cr.Status.AtProvider.Id = ""
	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return errors.New(errNotNbSetupKey)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Deleting", "cr", cr)

	setupKeyId := resolveSetupKeyLookupID(cr)
	if setupKeyId == "" {
		return errors.New("can't find setupKeyId")
	}
	err = client.SetupKeys.Delete(ctx, setupKeyId)
	if err != nil {
		return err
	}

	return nil
}
