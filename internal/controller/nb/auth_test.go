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

package auth

import (
	"context"
	"sync"
	"testing"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	apisv1alpha1 "github.com/crossplane/netbird-crossplane-provider/apis/v1alpha1"
	vpnv1alpha1 "github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
)

func testConnector() *SharedConnector {
	return &SharedConnector{
		usage:     resource.TrackerFn(func(_ context.Context, _ resource.Managed) error { return nil }),
		newAuthFn: NewAuthManager,
		cache:     sync.Map{},
	}
}

func testProviderConfig(uid types.UID, managementURI string) *apisv1alpha1.ProviderConfig {
	return &apisv1alpha1.ProviderConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			UID:  uid,
		},
		Spec: apisv1alpha1.ProviderConfigSpec{
			ManagementURI:   managementURI,
			CredentialsType: "token",
			Credentials: apisv1alpha1.ProviderCredentials{
				Source: xpv1.CredentialsSourceNone,
			},
		},
	}
}

// TestConnectReusesManagerWhileConfigUnchanged verifies the AuthManager cache
// still avoids rebuilding (and re-authenticating) when nothing changed.
func TestConnectReusesManagerWhileConfigUnchanged(t *testing.T) {
	c := testConnector()
	mg := &vpnv1alpha1.NbGroup{}
	pc := testProviderConfig("uid-1", "https://mgmt.example.com")

	first, err := c.Connect(context.Background(), mg, pc)
	if err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	second, err := c.Connect(context.Background(), mg, pc)
	if err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	if first != second {
		t.Fatal("expected the cached AuthManager to be reused for an unchanged ProviderConfig")
	}
}

// TestConnectRebuildsManagerOnConfigChange verifies that updating a
// ProviderConfig (same UID) invalidates the cached AuthManager, so endpoint or
// credential changes take effect without restarting the provider.
func TestConnectRebuildsManagerOnConfigChange(t *testing.T) {
	c := testConnector()
	mg := &vpnv1alpha1.NbGroup{}

	pc := testProviderConfig("uid-1", "http://mgmt.internal.svc:8080")
	stale, err := c.Connect(context.Background(), mg, pc)
	if err != nil {
		t.Fatalf("first Connect: %v", err)
	}

	// A ProviderConfig UPDATE keeps its UID but may change the endpoint —
	// e.g. management moving from plain HTTP in-cluster to public TLS.
	pc.Spec.ManagementURI = "https://mgmt.public.example.com"
	fresh, err := c.Connect(context.Background(), mg, pc)
	if err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	if stale == fresh {
		t.Fatal("expected a rebuilt AuthManager after ManagementURI changed on the same ProviderConfig")
	}
	if fresh.endpoint != "https://mgmt.public.example.com" {
		t.Fatalf("rebuilt AuthManager has endpoint %q, want the updated ManagementURI", fresh.endpoint)
	}

	// And the rebuilt manager is itself cached: a further unchanged Connect
	// reuses it.
	again, err := c.Connect(context.Background(), mg, pc)
	if err != nil {
		t.Fatalf("third Connect: %v", err)
	}
	if again != fresh {
		t.Fatal("expected the rebuilt AuthManager to be cached and reused")
	}
}
