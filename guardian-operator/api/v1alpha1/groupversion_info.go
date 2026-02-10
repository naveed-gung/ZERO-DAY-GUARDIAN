// Package v1alpha1 contains API Schema definitions for the guardian v1alpha1 API group.
//
// +kubebuilder:object:generate=true
// +groupName=guardian.zerodayguardian.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the API group and version for GuardianPolicy resources.
	GroupVersion = schema.GroupVersion{Group: "guardian.zerodayguardian.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionResource scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(&GuardianPolicy{}, &GuardianPolicyList{})
}
