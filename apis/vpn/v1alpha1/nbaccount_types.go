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

package v1alpha1

import (
	"reflect"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// NbAccountParameters are the configurable fields of a NbAccount.
type NbAccountParameters struct {
	Settings AccountSettings `json:"settings"`
}

// NbAccountObservation are the observable fields of a NbAccount.
type NbAccountObservation struct {
	Id       string          `json:"id"`
	Settings AccountSettings `json:"settings"`
	UserList []NbAccountUser `json:"user_list,omitempty"`
}

// AccountExtraSettings defines model for AccountExtraSettings.
type AccountExtraSettings struct {
	// NetworkTrafficLogsEnabled Enables or disables network traffic logs. If enabled, all network traffic logs from peers will be stored.
	NetworkTrafficLogsEnabled bool `json:"network_traffic_logs_enabled"`

	// NetworkTrafficLogsGroups Limits traffic logging to these groups. If unset all peers are enabled.
	// +optional
	NetworkTrafficLogsGroups []string `json:"network_traffic_logs_groups,omitempty"`

	// NetworkTrafficPacketCounterEnabled Enables or disables network traffic packet counter. If enabled, network packets and their size will be counted and reported. (This can have an slight impact on performance)
	NetworkTrafficPacketCounterEnabled bool `json:"network_traffic_packet_counter_enabled"`

	// PeerApprovalEnabled (Cloud only) Enables or disables peer approval globally. If enabled, all peers added will be in pending state until approved by an admin.
	PeerApprovalEnabled bool `json:"peer_approval_enabled"`

	// UserApprovalRequired Enables manual approval for new users joining via domain matching. When enabled, users are blocked with pending approval status until explicitly approved by an admin.
	// +optional
	UserApprovalRequired bool `json:"user_approval_required"`
}

// AccountSettings defines model for AccountSettings.
type AccountSettings struct {
	Extra *AccountExtraSettings `json:"extra,omitempty"`

	// GroupsPropagationEnabled Allows propagate the new user auto groups to peers that belongs to the user
	GroupsPropagationEnabled bool `json:"groups_propagation_enabled,omitempty"`

	// JwtAllowGroups List of groups to which users are allowed access
	JwtAllowGroups []string `json:"jwt_allow_groups,omitempty"`

	// JwtGroupsClaimName Name of the claim from which we extract groups names to add it to account groups.
	JwtGroupsClaimName string `json:"jwt_groups_claim_name,omitempty"`

	// JwtGroupsEnabled Allows extract groups from JWT claim and add it to account groups.
	JwtGroupsEnabled bool `json:"jwt_groups_enabled,omitempty"`

	// PeerInactivityExpiration Period of time of inactivity after which peer session expires (seconds).
	PeerInactivityExpiration int `json:"peer_inactivity_expiration"`

	// PeerInactivityExpirationEnabled Enables or disables peer inactivity expiration globally. After peer's session has expired the user has to log in (authenticate). Applies only to peers that were added by a user (interactive SSO login).
	PeerInactivityExpirationEnabled bool `json:"peer_inactivity_expiration_enabled"`

	// PeerLoginExpiration Period of time after which peer login expires (seconds).
	PeerLoginExpiration int `json:"peer_login_expiration"`

	// PeerLoginExpirationEnabled Enables or disables peer login expiration globally. After peer's login has expired the user has to log in (authenticate). Applies only to peers that were added by a user (interactive SSO login).
	PeerLoginExpirationEnabled bool `json:"peer_login_expiration_enabled"`

	// RegularUsersViewBlocked Allows blocking regular users from viewing parts of the system.
	RegularUsersViewBlocked bool `json:"regular_users_view_blocked"`

	// RoutingPeerDnsResolutionEnabled Enables or disables DNS resolution on the routing peers
	RoutingPeerDnsResolutionEnabled bool `json:"routing_peer_dns_resolution_enabled,omitempty"`
}

type NbAccountUser struct {
	UserEmail string   `json:"user_email"`
	Groups    []string `json:"user_groups,omitempty"`
	Role      string   `json:"role"`
}

// A NbAccountSpec defines the desired state of a NbAccount.
type NbAccountSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbAccountParameters `json:"forProvider"`
}

// A NbAccountStatus represents the observed state of a NbAccount.
type NbAccountStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbAccountObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbAccount is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbAccountSpec   `json:"spec"`
	Status NbAccountStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbAccountList contains a list of NbAccount
type NbAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbAccount `json:"items"`
}

// NbAccount type metadata.
var (
	NbAccountKind             = reflect.TypeOf(NbAccount{}).Name()
	NbAccountGroupKind        = schema.GroupKind{Group: Group, Kind: NbAccountKind}.String()
	NbAccountKindAPIVersion   = NbAccountKind + "." + SchemeGroupVersion.String()
	NbAccountGroupVersionKind = SchemeGroupVersion.WithKind(NbAccountKind)
)

func init() {
	SchemeBuilder.Register(&NbAccount{}, &NbAccountList{})
}
