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

package nbaccount

import (
	"context"
	"reflect"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
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
	"github.com/netbirdio/netbird/management/server/http/api"
)

const (
	errNotNbAccount = "managed resource is not a NbAccount custom resource"
)

// Setup adds a controller that reconciles NbAccount managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbAccountGroupKind)

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
		resource.ManagedKind(v1alpha1.NbAccountGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbAccount{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	*auth.SharedConnector
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	_, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return nil, errors.New(errNotNbAccount)
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
		log:         ctrl.Log.WithName("provider-nbaccount"),
	}, nil
}

type external struct {
	authManager *auth.AuthManager
	log         logr.Logger
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbAccount)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}

	accounts, err := client.Accounts.List(ctx)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		// Don't swallow transient errors — Crossplane should requeue, not call Create.
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to list accounts")
	}

	accountusers, err := client.Users.List(ctx)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to list users for account observation")
	}

	allgroups, err := client.Groups.List(ctx)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to list groups for account observation")
	}

	account := accounts[0]
	uptodate := isUpToDate(*cr, account, c)

	cr.Status.AtProvider = v1alpha1.NbAccountObservation{
		Id:       account.Id,
		Settings: *ApitoNbAccountSettings(account.Settings),
		UserList: *ApitoNbAccountUsers(accountusers, allgroups),
	}

	meta.SetExternalName(cr, account.Id)
	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  uptodate,
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func isUpToDate(nbaccount v1alpha1.NbAccount, apiaccount api.Account, c *external) bool {
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.Extra.NetworkTrafficLogsEnabled, apiaccount.Settings.Extra.NetworkTrafficLogsEnabled) {
		c.log.Info("extra settings NetworkTrafficLogsEnabled not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.Extra.NetworkTrafficPacketCounterEnabled, apiaccount.Settings.Extra.NetworkTrafficPacketCounterEnabled) {
		c.log.Info("extra settings NetworkTrafficPacketCounterEnabled not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.Extra.PeerApprovalEnabled, apiaccount.Settings.Extra.PeerApprovalEnabled) {
		c.log.Info("extra settings PeerApprovalEnabled not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.GroupsPropagationEnabled, *apiaccount.Settings.GroupsPropagationEnabled) {
		c.log.Info("GroupsPropagationEnabled not equal")
		return false
	}
	if !reflect.DeepEqual(nbaccount.Spec.ForProvider.Settings.JwtAllowGroups, *apiaccount.Settings.JwtAllowGroups) {
		c.log.Info("JwtAllowGroups not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.JwtGroupsClaimName, *apiaccount.Settings.JwtGroupsClaimName) {
		c.log.Info("JwtGroupsClaimName not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.JwtGroupsEnabled, *apiaccount.Settings.JwtGroupsEnabled) {
		c.log.Info("JwtGroupsEnabled not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.PeerInactivityExpiration, apiaccount.Settings.PeerInactivityExpiration) {
		c.log.Info("PeerInactivityExpiration not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.PeerInactivityExpirationEnabled, apiaccount.Settings.PeerInactivityExpirationEnabled) {
		c.log.Info("PeerInactivityExpirationEnabled not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.PeerLoginExpiration, apiaccount.Settings.PeerLoginExpiration) {
		c.log.Info("PeerLoginExpiration not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.PeerLoginExpirationEnabled, apiaccount.Settings.PeerLoginExpirationEnabled) {
		c.log.Info("PeerLoginExpirationEnabled not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.RegularUsersViewBlocked, apiaccount.Settings.RegularUsersViewBlocked) {
		c.log.Info("RegularUsersViewBlocked not equal")
		return false
	}
	if !cmp.Equal(nbaccount.Spec.ForProvider.Settings.RoutingPeerDnsResolutionEnabled, *apiaccount.Settings.RoutingPeerDnsResolutionEnabled) {
		c.log.Info("RoutingPeerDnsResolutionEnabled not equal")
		return false
	}
	return true
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbAccount)
	}
	c.log.Info("Creating", "cr", cr)
	return managed.ExternalCreation{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbAccount)
	}

	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}

	accountId := meta.GetExternalName(cr)
	if accountId == "" {
		return managed.ExternalUpdate{}, errors.New("can't find accountid")
	}

	accountsettings := NbToApiAccountSettings(cr.Spec.ForProvider.Settings)
	_, err = client.Accounts.Update(ctx, accountId, api.AccountRequest{
		Settings: *accountsettings,
	})

	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return errors.New(errNotNbAccount)
	}
	c.log.Info("Deleting", "cr", cr)
	return nil
}

func ApitoNbAccountSettings(p api.AccountSettings) *v1alpha1.AccountSettings {
	accountsettings := v1alpha1.AccountSettings{
		Extra:                           (*v1alpha1.AccountExtraSettings)(p.Extra),
		GroupsPropagationEnabled:        *p.GroupsPropagationEnabled,
		JwtAllowGroups:                  *p.JwtAllowGroups,
		JwtGroupsClaimName:              *p.JwtGroupsClaimName,
		JwtGroupsEnabled:                *p.JwtGroupsEnabled,
		PeerInactivityExpiration:        p.PeerInactivityExpiration,
		PeerLoginExpiration:             p.PeerLoginExpiration,
		PeerInactivityExpirationEnabled: p.PeerInactivityExpirationEnabled,
		PeerLoginExpirationEnabled:      p.PeerLoginExpirationEnabled,
		RegularUsersViewBlocked:         p.RegularUsersViewBlocked,
		RoutingPeerDnsResolutionEnabled: *p.RoutingPeerDnsResolutionEnabled,
	}
	return &accountsettings
}

func NbToApiAccountSettings(p v1alpha1.AccountSettings) *api.AccountSettings {
	extrasettings := api.AccountExtraSettings{
		NetworkTrafficLogsEnabled:          p.Extra.NetworkTrafficLogsEnabled,
		NetworkTrafficPacketCounterEnabled: p.Extra.NetworkTrafficPacketCounterEnabled,
		PeerApprovalEnabled:                p.Extra.PeerApprovalEnabled,
	}
	accountsettings := api.AccountSettings{
		Extra:                           &extrasettings,
		GroupsPropagationEnabled:        &p.GroupsPropagationEnabled,
		JwtAllowGroups:                  &p.JwtAllowGroups,
		JwtGroupsClaimName:              &p.JwtGroupsClaimName,
		JwtGroupsEnabled:                &p.JwtGroupsEnabled,
		PeerInactivityExpiration:        p.PeerInactivityExpiration,
		PeerLoginExpiration:             p.PeerLoginExpiration,
		PeerInactivityExpirationEnabled: p.PeerInactivityExpirationEnabled,
		PeerLoginExpirationEnabled:      p.PeerLoginExpirationEnabled,
		RegularUsersViewBlocked:         p.RegularUsersViewBlocked,
		RoutingPeerDnsResolutionEnabled: &p.RoutingPeerDnsResolutionEnabled,
	}
	return &accountsettings
}

func ApitoNbAccountUsers(accountusers []api.User, allgroups []api.Group) *[]v1alpha1.NbAccountUser {
	var nbaccountusers []v1alpha1.NbAccountUser

	for _, accountuser := range accountusers {
		if accountuser.IsServiceUser == nil || *accountuser.IsServiceUser {
			continue
		}

		nbaccountusers = append(nbaccountusers, v1alpha1.NbAccountUser{
			UserEmail: accountuser.Email,
			Groups:    *GetGroupIds(accountuser.AutoGroups, allgroups),
			Role:      accountuser.Role,
		})
	}

	return &nbaccountusers
}

func GetGroupIds(groupids []string, allgroups []api.Group) *[]string {
	groupnames := make([]string, len(groupids))
	for i, groupid := range groupids {
		for _, group := range allgroups {
			if group.Id == groupid {
				groupnames[i] = group.Name
				break
			}
		}
	}
	return &groupnames
}
