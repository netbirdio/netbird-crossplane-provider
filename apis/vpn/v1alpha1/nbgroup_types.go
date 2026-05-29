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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	netbirdapi "github.com/netbirdio/netbird/shared/management/http/api"
)

// NbGroupParameters are the configurable fields of a NbGroup.
type NbGroupParameters struct {
	Name string `json:"name"`
}

// NbGroupObservation are the observable fields of a NbGroup.
type NbGroupObservation struct {
	// Id Group ID
	Id string `json:"id"`

	// Issued How the group was issued (api, integration, jwt)
	Issued *netbirdapi.GroupIssued `json:"issued,omitempty"`

	// Peers List of peers object
	Peers []netbirdapi.PeerMinimum `json:"peers,omitempty"`

	// PeersCount Count of peers associated to the group
	PeersCount int                   `json:"peers_count,omitempty"`
	Resources  []netbirdapi.Resource `json:"resources,omitempty"`

	// ResourcesCount Count of resources associated to the group
	ResourcesCount int `json:"resources_count,omitempty"`
}

// A NbGroupSpec defines the desired state of a NbGroup.
type NbGroupSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbGroupParameters `json:"forProvider"`
}

// A NbGroupStatus represents the observed state of a NbGroup.
type NbGroupStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbGroup is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbGroupSpec   `json:"spec"`
	Status NbGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbGroupList contains a list of NbGroup
type NbGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbGroup `json:"items"`
}

// NbGroup type metadata.
var (
	NbGroupKind             = reflect.TypeOf(NbGroup{}).Name()
	NbGroupGroupKind        = schema.GroupKind{Group: Group, Kind: NbGroupKind}.String()
	NbGroupKindAPIVersion   = NbGroupKind + "." + SchemeGroupVersion.String()
	NbGroupGroupVersionKind = SchemeGroupVersion.WithKind(NbGroupKind)
)

func init() {
	SchemeBuilder.Register(&NbGroup{}, &NbGroupList{})
}
