package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GuardianPolicySpec defines the desired security monitoring configuration.
type GuardianPolicySpec struct {
	// NodeSelector for targeting specific nodes with eBPF monitoring.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Detection configures the detection engine behavior.
	Detection DetectionConfig `json:"detection"`

	// Response configures automated response actions.
	Response ResponseConfig `json:"response"`

	// ThreatIntel configures threat intelligence integration.
	// +optional
	ThreatIntel ThreatIntelConfig `json:"threatIntel,omitempty"`

	// SIEM configures SIEM forwarding.
	// +optional
	SIEM SIEMConfig `json:"siem,omitempty"`
}

// DetectionConfig defines detection parameters.
type DetectionConfig struct {
	// Enabled toggles the detection engine.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// SeverityThreshold is the minimum severity for automated actions.
	// +kubebuilder:validation:Enum=CRITICAL;HIGH;MEDIUM;LOW;INFO
	// +kubebuilder:default="HIGH"
	SeverityThreshold string `json:"severityThreshold"`

	// EnabledDetectors lists which detectors to activate.
	// +kubebuilder:default={"container-escape","cryptojacking","lateral-movement","sequence-analysis"}
	EnabledDetectors []string `json:"enabledDetectors"`
}

// ResponseConfig defines automated response behavior.
type ResponseConfig struct {
	// DryRun mode logs actions without executing them.
	// +kubebuilder:default=true
	DryRun bool `json:"dryRun"`

	// RateLimitPerMinute caps automated actions per minute.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=10
	RateLimitPerMinute int `json:"rateLimitPerMinute"`

	// ApprovedNamespaces restricts which namespaces can receive automated actions.
	// Empty list means all non-excluded namespaces.
	// +optional
	ApprovedNamespaces []string `json:"approvedNamespaces,omitempty"`

	// ExcludedNamespaces are always protected from automated actions.
	// kube-system, kube-public, kube-node-lease are always excluded.
	// +optional
	ExcludedNamespaces []string `json:"excludedNamespaces,omitempty"`
}

// ThreatIntelConfig defines threat intelligence provider settings.
type ThreatIntelConfig struct {
	// VirusTotal API key secret reference.
	// +optional
	VirusTotalSecretRef *SecretRef `json:"virusTotalSecretRef,omitempty"`

	// AbuseIPDB API key secret reference.
	// +optional
	AbuseIPDBSecretRef *SecretRef `json:"abuseIPDBSecretRef,omitempty"`

	// AlienVault OTX API key secret reference.
	// +optional
	OTXSecretRef *SecretRef `json:"otxSecretRef,omitempty"`
}

// SIEMConfig defines SIEM forwarding targets.
type SIEMConfig struct {
	// Splunk HEC configuration.
	// +optional
	Splunk *SplunkConfig `json:"splunk,omitempty"`

	// Elasticsearch configuration.
	// +optional
	Elastic *ElasticConfig `json:"elastic,omitempty"`
}

// SplunkConfig defines Splunk HEC integration.
type SplunkConfig struct {
	Enabled  bool      `json:"enabled"`
	HECUrl   string    `json:"hecUrl"`
	TokenRef SecretRef `json:"tokenRef"`
	Index    string    `json:"index,omitempty"`
}

// ElasticConfig defines Elasticsearch integration.
type ElasticConfig struct {
	Enabled   bool      `json:"enabled"`
	URL       string    `json:"url"`
	APIKeyRef SecretRef `json:"apiKeyRef"`
	Index     string    `json:"index,omitempty"`
}

// SecretRef references a key within a Kubernetes Secret.
type SecretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// GuardianPolicyStatus defines the observed state.
type GuardianPolicyStatus struct {
	// Phase of the GuardianPolicy (Pending, Running, Degraded, Error).
	// +kubebuilder:validation:Enum=Pending;Running;Degraded;Error
	Phase string `json:"phase,omitempty"`

	// MonitoredNodes is the count of nodes with active eBPF monitors.
	MonitoredNodes int `json:"monitoredNodes,omitempty"`

	// TotalDetections since the policy was applied.
	TotalDetections int64 `json:"totalDetections,omitempty"`

	// TotalActions executed since the policy was applied.
	TotalActions int64 `json:"totalActions,omitempty"`

	// LastDetectionTime is the timestamp of the most recent detection.
	// +optional
	LastDetectionTime *metav1.Time `json:"lastDetectionTime,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Nodes",type=integer,JSONPath=`.status.monitoredNodes`
// +kubebuilder:printcolumn:name="Detections",type=integer,JSONPath=`.status.totalDetections`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:resource:shortName=gp

// GuardianPolicy is the Schema for the guardianpolicies API.
type GuardianPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GuardianPolicySpec   `json:"spec,omitempty"`
	Status GuardianPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GuardianPolicyList contains a list of GuardianPolicy.
type GuardianPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GuardianPolicy `json:"items"`
}
