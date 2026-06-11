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

package nbaccesstoken

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
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
	errNotNbAccessToken  = "managed resource is not a NbAccessToken custom resource"
	accessTokenSecretKey = "NB_API_KEY"
)

// Setup adds a controller that reconciles NbAccessToken managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbAccessTokenGroupKind)

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
		resource.ManagedKind(v1alpha1.NbAccessTokenGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbAccessToken{}).
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
	_, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return nil, errors.New(errNotNbAccessToken)
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
		log:         ctrl.Log.WithName("provider-nbaccesstoken"),
	}, nil
}

// authClient is the subset of the netbird auth manager used by this controller.
type authClient interface {
	GetClient(ctx context.Context) (*netbird.Client, error)
	ForceRefresh(ctx context.Context) error
}

// external implements managed.ExternalClient for the NbAccessToken managed resource.
type external struct {
	authManager authClient
	log         logr.Logger
}

// Observe checks whether the NbAccessToken currently exists in netbird and updates status.
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbAccessToken)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Observing", "cr", cr)

	externalName := meta.GetExternalName(cr)
	lookupID := resolveAccessTokenLookupID(cr)

	var userid string
	if cr.Spec.ForProvider.UserName != nil {
		users, err := client.Users.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.log.Error(err, "Token invalid error detected during get, forcing token refresh")
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to list users for access token lookup")
		}
		var apiuser *nbapi.User
		for _, user := range users {
			if user.IsServiceUser != nil && *user.IsServiceUser && (user.Name == *cr.Spec.ForProvider.UserName) {
				apiuser = &user
				break
			}
		}
		if apiuser == nil {
			return managed.ExternalObservation{ResourceExists: false}, nil
		}
		userid = apiuser.Id
	} else if cr.Spec.ForProvider.UserId != nil {
		userid = *cr.Spec.ForProvider.UserId
	} else {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	// The lookup ID may be empty (fresh MR, or Update cleared both external-name and
	// status.AtProvider.Id when rotating an expired token) or hold a non-ID value
	// (object name or composition-stamped display name). Try it as an ID first, and
	// otherwise fall back to adoption by Name under the resolved user so a Create
	// whose external-name persist failed doesn't mint a duplicate PAT.
	var accesstoken *nbapi.PersonalAccessToken
	if lookupID != "" && lookupID != cr.Name && lookupID != cr.Spec.ForProvider.Name {
		var err error
		accesstoken, err = client.Tokens.Get(ctx, userid, lookupID)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.log.Error(err, "Token invalid error detected during get, forcing token refresh")
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			if !isAccessTokenNotFoundError(err) {
				// Don't swallow transient errors — Crossplane should requeue, not mint a duplicate PAT.
				return managed.ExternalObservation{}, errors.Wrapf(err, "failed to observe access token %q", lookupID)
			}
			c.log.Info("access token not found by id, attempting adoption by name", "lookup-id", lookupID)
		}
	}
	if accesstoken == nil {
		tokens, err := client.Tokens.List(ctx, userid)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.log.Error(err, "Token invalid error detected during list, forcing token refresh")
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			// Don't swallow transient errors — a failed list must not look like "doesn't exist".
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to list access tokens for adoption")
		}
		for _, token := range tokens {
			if token.Name == cr.Spec.ForProvider.Name {
				c.log.Info("adopting existing access token", "token-id", token.Id)
				meta.SetExternalName(cr, token.Id)
				// Identity is persisted via status.atProvider.id (external-name set
				// during Observe is not persisted by the runtime), which the lookup
				// resolver prefers. Report up-to-date: Update would rotate (delete)
				// the token, which must stay reserved for the expired path — an
				// adopted expired token is rotated on the next reconcile's ID lookup.
				cr.Status.AtProvider.Id = token.Id
				cr.Status.SetConditions(xpv1.Available())
				return managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true,
				}, nil
			}
		}
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	// Repair stale or missing external-name annotations after recovering via status ID.
	if externalName != accesstoken.Id {
		meta.SetExternalName(cr, accesstoken.Id)
	}

	var lastused *string
	if accesstoken.LastUsed != nil {
		lastusedstring := accesstoken.LastUsed.Local().String()
		lastused = &lastusedstring
	}
	if accesstoken.ExpirationDate.Before(time.Now()) {
		// Token exists but is expired: trigger Update, not Create
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}
	cr.Status.AtProvider = v1alpha1.NbAccessTokenObservation{
		Id:             accesstoken.Id,
		Name:           accesstoken.Name,
		ExpirationDate: accesstoken.ExpirationDate.String(),
		LastUsed:       lastused,
	}
	cr.Status.SetConditions(xpv1.Available())
	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true, // update logic can be added if needed
	}, nil
}

// resolveAccessTokenLookupID picks the best identifier to use when looking the access
// token up by ID, falling back to the recorded provider ID when the external-name
// annotation is missing or was defaulted to the Kubernetes object name by an
// older reconcile (before WithInitializers disabled the NameAsExternalName default).
func resolveAccessTokenLookupID(cr *v1alpha1.NbAccessToken) string {
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

// isAccessTokenNotFoundError matches the netbird REST API's not-found messages
// for personal access tokens — both the "token: <id> not found" form returned by
// the SetupKeys layer and the "PAT: <id> not found" form returned by the token
// store.
func isAccessTokenNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	if !strings.Contains(errStr, "not found") {
		return false
	}
	return strings.Contains(errStr, "token") || strings.Contains(errStr, "pat")
}

func (c *external) getUserID(ctx context.Context, cr *v1alpha1.NbAccessToken, client *netbird.Client) (string, error) {
	if cr.Spec.ForProvider.UserName != nil {

		users, err := client.Users.List(ctx)
		if err != nil {
			return "", errors.Wrap(err, "failed to list users")
		}
		for _, user := range users {
			if user.Name == *cr.Spec.ForProvider.UserName {
				return user.Id, nil
			}
		}
		return "", errors.New("user not found")
	}
	return *cr.Spec.ForProvider.UserId, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbAccessToken)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Creating", "cr", cr)
	var userid string
	if cr.Spec.ForProvider.UserName != nil {
		users, err := client.Users.List(ctx)
		if err != nil {
			return managed.ExternalCreation{}, err
		}
		var apiuser nbapi.User
		for _, user := range users {
			if user.Name == *cr.Spec.ForProvider.UserName {
				apiuser = user
			}
		}
		userid = apiuser.Id
	} else {
		userid = *cr.Spec.ForProvider.UserId
	}
	accesstoken, err := client.Tokens.Create(ctx, userid, nbapi.PersonalAccessTokenRequest{
		ExpiresIn: cr.Spec.ForProvider.ExpiresIn,
		Name:      cr.Spec.ForProvider.Name,
	})
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	meta.SetExternalName(cr, accesstoken.PersonalAccessToken.Id)

	cd := managed.ConnectionDetails{
		accessTokenSecretKey: []byte(accesstoken.PlainToken),
	}
	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: cd,
	}, nil
}

// for now only called when token expired
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbAccessToken)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}

	c.log.Info("Updating", "cr", cr)
	lookupID := resolveAccessTokenLookupID(cr)
	if lookupID == "" {
		return managed.ExternalUpdate{}, errors.New("can't find access token id")
	}
	userid, err := c.getUserID(ctx, cr, client)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	if err := client.Tokens.Delete(ctx, userid, lookupID); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to delete expired token")
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
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return errors.New(errNotNbAccessToken)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}

	lookupID := resolveAccessTokenLookupID(cr)
	if lookupID == "" {
		return errors.New("can't find access token id")
	}
	c.log.Info("Deleting", "cr", cr)
	var userid string
	if cr.Spec.ForProvider.UserName != nil {
		users, err := client.Users.List(ctx)
		if err != nil {
			return err
		}
		var apiuser nbapi.User
		for _, user := range users {
			if user.Name == *cr.Spec.ForProvider.UserName {
				apiuser = user
			}
		}
		userid = apiuser.Id
	} else {
		userid = *cr.Spec.ForProvider.UserId
	}
	return client.Tokens.Delete(ctx, userid, lookupID)
}
