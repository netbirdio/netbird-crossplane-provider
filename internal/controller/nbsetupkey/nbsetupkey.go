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

	// The lookup ID may be empty (fresh MR, or Update cleared both external-name and
	// status.AtProvider.Id when rotating a revoked/expired key) or hold a non-ID
	// value (object name or display-name adoption hint). Try it as an ID
	// first, and otherwise fall back to adoption by Name so a Create whose
	// external-name persist failed doesn't mint a duplicate key.
	var setupkey *api.SetupKey
	if lookupID != "" && lookupID != cr.Name && lookupID != cr.Spec.ForProvider.Name {
		var err error
		setupkey, err = client.SetupKeys.Get(ctx, lookupID)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			if !isSetupKeyNotFoundError(err) {
				// Don't swallow transient errors — Crossplane should requeue, not mint a duplicate key.
				return managed.ExternalObservation{}, errors.Wrapf(err, "failed to observe setup key %q", lookupID)
			}
			c.log.Info("setup key not found by id, attempting adoption by name", "lookup-id", lookupID)
		}
	}
	if setupkey == nil {
		// Adoption by Name. Only valid keys are adopted: a revoked or expired key
		// with a matching name is rotation leftover, and a deleted-but-still-listed
		// key must not be re-adopted or rotation would never converge on Create.
		keys, err := client.SetupKeys.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			// Don't swallow transient errors — a failed list must not look like "doesn't exist".
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to list setup keys for adoption")
		}
		// Prefer a valid key. A revoked spec falls back to any key of that name,
		// so a still-valid key is the one the next reconcile revokes.
		var adopt *api.SetupKey
		for i := range keys {
			key := &keys[i]
			if key.Name != cr.Spec.ForProvider.Name {
				continue
			}
			if !key.Revoked && key.Expires.After(time.Now()) {
				adopt = key
				break
			}
			if cr.Spec.ForProvider.Revoked && adopt == nil {
				adopt = key
			}
		}
		if adopt == nil {
			return managed.ExternalObservation{ResourceExists: false}, nil
		}
		c.log.Info("adopting existing setup key", "setup-key-id", adopt.Id)
		meta.SetExternalName(cr, adopt.Id)
		// Identity is persisted via status.atProvider.id (external-name set
		// during Observe is not persisted by the runtime), which the lookup
		// resolver prefers. Report up-to-date: Update would rotate (delete)
		// the key, which must stay reserved for the expired/revoked path.
		cr.Status.AtProvider.Id = adopt.Id
		cr.Status.SetConditions(xpv1.Available())
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: true,
		}, nil
	}

	// Repair stale or missing external-name annotations after recovering via status ID.
	if externalName != setupkey.Id {
		meta.SetExternalName(cr, setupkey.Id)
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

	expired := setupkey.Expires.Before(time.Now())
	if cr.Spec.ForProvider.Revoked {
		// Revocation is one-way in netbird, so a revoked or expired key is the
		// desired end state; only a still-valid key needs Update to revoke it.
		cr.Status.SetConditions(xpv1.Available())
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: setupkey.Revoked || expired,
		}, nil
	}
	if expired || setupkey.Revoked {
		// Token setupkey exists but is expired or revoked: trigger Update, not Create
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  sameGroups(cr.Spec.ForProvider.AutoGroups, setupkey.AutoGroups),
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// sameGroups compares auto-group ID lists ignoring order; nil and empty are equal.
func sameGroups(want, got []string) bool {
	if len(want) != len(got) {
		return false
	}
	seen := make(map[string]int, len(want))
	for _, g := range want {
		seen[g]++
	}
	for _, g := range got {
		if seen[g] == 0 {
			return false
		}
		seen[g]--
	}
	return true
}

// needsRotation reports whether a key can no longer enroll peers while the spec
// still wants a usable key. netbird cannot un-revoke, so the key is replaced.
func needsRotation(cr *v1alpha1.NbSetupKey, setupkey *api.SetupKey) bool {
	return !cr.Spec.ForProvider.Revoked && (setupkey.Revoked || setupkey.Expires.Before(time.Now()))
}

// keyRequest is the PUT body for the fields netbird lets an existing key change.
func keyRequest(cr *v1alpha1.NbSetupKey) api.PutApiSetupKeysKeyIdJSONRequestBody {
	groups := cr.Spec.ForProvider.AutoGroups
	if groups == nil {
		groups = []string{}
	}
	return api.PutApiSetupKeysKeyIdJSONRequestBody{AutoGroups: groups, Revoked: cr.Spec.ForProvider.Revoked}
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
	case cr.Status.AtProvider.Id != "" && cr.Status.AtProvider.Id != externalName &&
		(externalName == cr.GetName() || externalName == cr.Spec.ForProvider.Name):
		// Recover when the external name holds the Kubernetes object name (older
		// reconciles) or the netbird display name (used as an adoption hint).
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
	if cr.Spec.ForProvider.Revoked {
		// netbird cannot create a revoked key. Revoke it straight away; on failure
		// the next Observe sees a valid key and Update revokes it.
		if _, err := client.SetupKeys.Update(ctx, setupkey.Id, keyRequest(cr)); err != nil {
			c.log.Info("revoking new setup key failed, will retry on update", "setup-key-id", setupkey.Id, "error", err.Error())
		}
	}
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
	setupkey, err := client.SetupKeys.Get(ctx, setupKeyId)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrapf(err, "failed to get setup key %q", setupKeyId)
	}
	if !needsRotation(cr, setupkey) {
		// Revocation and auto-group changes apply in place and keep the key value.
		if _, err := client.SetupKeys.Update(ctx, setupKeyId, keyRequest(cr)); err != nil {
			return managed.ExternalUpdate{}, errors.Wrapf(err, "failed to update setup key %q", setupKeyId)
		}
		return managed.ExternalUpdate{}, nil
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
