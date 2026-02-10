package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	guardianv1alpha1 "github.com/naveed-gung/zero-day-guardian/guardian-operator/api/v1alpha1"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = guardianv1alpha1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	return s
}

func newTestPolicy(name, namespace string) *guardianv1alpha1.GuardianPolicy {
	return &guardianv1alpha1.GuardianPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: guardianv1alpha1.GuardianPolicySpec{
			NodeSelector: map[string]string{
				"kubernetes.io/os": "linux",
			},
			Detection: guardianv1alpha1.DetectionConfig{
				Enabled:           true,
				SeverityThreshold: "HIGH",
				EnabledDetectors:  []string{"container-escape", "cryptojacking", "lateral-movement", "sequence-analysis"},
			},
			Response: guardianv1alpha1.ResponseConfig{
				DryRun:             false,
				RateLimitPerMinute: 10,
				ExcludedNamespaces: []string{"kube-system"},
			},
		},
	}
}

func TestReconcile_CreatesPolicyAndDaemonSet(t *testing.T) {
	scheme := newTestScheme()
	policy := newTestPolicy("test-policy", "guardian-system")

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(policy).
		Build()

	r := &GuardianPolicyReconciler{
		Client: cl,
		Scheme: scheme,
		DaemonSetManager: &DaemonSetManager{
			Client:    cl,
			Namespace: "guardian-system",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "guardian-system",
		},
	}

	result, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)
}

func TestReconcile_NotFound_NoError(t *testing.T) {
	scheme := newTestScheme()

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := &GuardianPolicyReconciler{
		Client: cl,
		Scheme: scheme,
		DaemonSetManager: &DaemonSetManager{
			Client:    cl,
			Namespace: "guardian-system",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "nonexistent",
			Namespace: "guardian-system",
		},
	}

	result, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.Requeue)
}

func TestDaemonSetManager_BuildDaemonSet(t *testing.T) {
	scheme := newTestScheme()

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	mgr := &DaemonSetManager{
		Client:    cl,
		Namespace: "guardian-system",
	}

	policy := newTestPolicy("build-test", "guardian-system")
	ds := mgr.buildDaemonSet(policy)

	// Verify DaemonSet structure
	assert.Equal(t, "guardian-monitor-build-test", ds.Name)
	assert.Equal(t, "guardian-system", ds.Namespace)
	assert.True(t, ds.Spec.Template.Spec.HostPID)
	assert.Equal(t, "guardian-monitor", ds.Spec.Template.Spec.ServiceAccountName)

	// Verify containers
	require.Len(t, ds.Spec.Template.Spec.Containers, 2)
	assert.Equal(t, "ebpf-monitor", ds.Spec.Template.Spec.Containers[0].Name)
	assert.Equal(t, "detection-engine", ds.Spec.Template.Spec.Containers[1].Name)

	// Verify ebpf-monitor is privileged
	assert.True(t, *ds.Spec.Template.Spec.Containers[0].SecurityContext.Privileged)

	// Verify volumes
	require.Len(t, ds.Spec.Template.Spec.Volumes, 4)
	assert.Equal(t, "ringbuf", ds.Spec.Template.Spec.Volumes[0].Name)
	assert.NotNil(t, ds.Spec.Template.Spec.Volumes[0].VolumeSource.EmptyDir)
	assert.Equal(t, corev1.StorageMediumMemory, ds.Spec.Template.Spec.Volumes[0].VolumeSource.EmptyDir.Medium)
	assert.Equal(t, "evidence", ds.Spec.Template.Spec.Volumes[3].Name)

	// Verify hostNetwork
	assert.True(t, ds.Spec.Template.Spec.HostNetwork)

	// Verify node selector passthrough
	assert.Equal(t, map[string]string{"kubernetes.io/os": "linux"}, ds.Spec.Template.Spec.NodeSelector)
}

func TestBuildDetectionEnv(t *testing.T) {
	policy := newTestPolicy("env-test", "guardian-system")
	policy.Spec.ThreatIntel = guardianv1alpha1.ThreatIntelConfig{
		VirusTotalSecretRef: &guardianv1alpha1.SecretRef{Name: "guardian-secrets", Key: "vt-key"},
		AbuseIPDBSecretRef:  &guardianv1alpha1.SecretRef{Name: "guardian-secrets", Key: "abuseipdb-key"},
	}

	envs := buildDetectionEnv(policy)

	// Base envs: RINGBUFFER_PATH, DRY_RUN, RATE_LIMIT, NODE_NAME, POD_NAME = 5
	// Threat intel: VT + AbuseIPDB = 2
	assert.Len(t, envs, 7)

	// Verify secret refs
	var vtEnv, abuseEnv *corev1.EnvVar
	for i := range envs {
		switch envs[i].Name {
		case "GUARDIAN_THREAT_INTEL_VIRUS_TOTAL_API_KEY":
			vtEnv = &envs[i]
		case "GUARDIAN_THREAT_INTEL_ABUSE_IP_DB_API_KEY":
			abuseEnv = &envs[i]
		}
	}

	require.NotNil(t, vtEnv)
	assert.Equal(t, "guardian-secrets", vtEnv.ValueFrom.SecretKeyRef.Name)
	assert.Equal(t, "vt-key", vtEnv.ValueFrom.SecretKeyRef.Key)

	require.NotNil(t, abuseEnv)
	assert.Equal(t, "guardian-secrets", abuseEnv.ValueFrom.SecretKeyRef.Name)
	assert.Equal(t, "abuseipdb-key", abuseEnv.ValueFrom.SecretKeyRef.Key)
}

func TestDaemonSetName(t *testing.T) {
	policy := &guardianv1alpha1.GuardianPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "production"},
	}
	assert.Equal(t, "guardian-monitor-production", daemonSetName(policy))
}
