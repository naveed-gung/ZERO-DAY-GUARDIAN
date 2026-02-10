package controller

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	guardianv1alpha1 "github.com/naveed-gung/zero-day-guardian/guardian-operator/api/v1alpha1"
)

const (
	ebpfMonitorImage    = "ghcr.io/naveed-gung/zero-day-guardian/ebpf-monitor:latest"
	detectionImage      = "ghcr.io/naveed-gung/zero-day-guardian/detection-engine:latest"
	operatorNameLabel   = "app.kubernetes.io/managed-by"
	operatorNameValue   = "guardian-operator"
	componentLabel      = "app.kubernetes.io/component"
	ringBufferMountPath = "/var/guardian/ringbuf"
	ringBufferFileName  = "events.buf"
)

// DaemonSetManager manages the Guardian DaemonSet lifecycle.
type DaemonSetManager struct {
	client.Client
	Namespace string
}

// Reconcile ensures the DaemonSet exists and matches the policy spec.
// Returns the number of ready nodes.
func (m *DaemonSetManager) Reconcile(ctx context.Context, policy *guardianv1alpha1.GuardianPolicy) (int, error) {
	logger := log.FromContext(ctx)
	desired := m.buildDaemonSet(policy)

	// Set owner reference for garbage collection
	if err := controllerutil.SetControllerReference(policy, desired, m.Scheme()); err != nil {
		return 0, fmt.Errorf("failed to set owner reference: %w", err)
	}

	// Check if DaemonSet exists
	var existing appsv1.DaemonSet
	err := m.Get(ctx, types.NamespacedName{
		Name:      desired.Name,
		Namespace: desired.Namespace,
	}, &existing)

	if errors.IsNotFound(err) {
		logger.Info("Creating Guardian DaemonSet", "name", desired.Name)
		if err := m.Create(ctx, desired); err != nil {
			return 0, fmt.Errorf("failed to create DaemonSet: %w", err)
		}
		return 0, nil
	} else if err != nil {
		return 0, fmt.Errorf("failed to get DaemonSet: %w", err)
	}

	// Update existing DaemonSet
	existing.Spec = desired.Spec
	existing.Labels = desired.Labels
	if err := m.Update(ctx, &existing); err != nil {
		return 0, fmt.Errorf("failed to update DaemonSet: %w", err)
	}

	return int(existing.Status.NumberReady), nil
}

// Delete removes the Guardian DaemonSet.
func (m *DaemonSetManager) Delete(ctx context.Context, policy *guardianv1alpha1.GuardianPolicy) error {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      daemonSetName(policy),
			Namespace: m.Namespace,
		},
	}

	if err := m.Client.Delete(ctx, ds); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete DaemonSet: %w", err)
	}

	return nil
}

// Scheme returns the runtime scheme from the client for owner references.
func (m *DaemonSetManager) Scheme() *runtime.Scheme {
	return m.Client.Scheme()
}

func (m *DaemonSetManager) buildDaemonSet(policy *guardianv1alpha1.GuardianPolicy) *appsv1.DaemonSet {
	name := daemonSetName(policy)

	labels := map[string]string{
		"app.kubernetes.io/name":    "zero-day-guardian",
		"app.kubernetes.io/part-of": "zero-day-guardian",
		operatorNameLabel:           operatorNameValue,
		componentLabel:              "monitor",
	}

	privileged := true
	hostPID := true
	hostNetwork := true
	runAsRoot := int64(0)

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: m.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name": "zero-day-guardian",
					componentLabel:           "monitor",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						"prometheus.io/scrape": "true",
						"prometheus.io/port":   "8081",
						"prometheus.io/path":   "/actuator/prometheus",
					},
				},
				Spec: corev1.PodSpec{
					HostPID:            hostPID,
					HostNetwork:        hostNetwork,
					ServiceAccountName: "guardian-monitor",
					NodeSelector:       policy.Spec.NodeSelector,
					Tolerations: []corev1.Toleration{
						{
							Operator: corev1.TolerationOpExists,
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "ebpf-monitor",
							Image: ebpfMonitorImage,
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
								RunAsUser:  &runAsRoot,
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "ringbuf",
									MountPath: ringBufferMountPath,
								},
								{
									Name:      "sys-kernel-debug",
									MountPath: "/sys/kernel/debug",
									ReadOnly:  true,
								},
								{
									Name:      "proc",
									MountPath: "/host/proc",
									ReadOnly:  true,
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "RING_BUFFER_PATH",
									Value: ringBufferMountPath + "/" + ringBufferFileName,
								},
								{
									Name: "NODE_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "spec.nodeName",
										},
									},
								},
								{
									Name: "POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.name",
										},
									},
								},
							},
						},
						{
							Name:  "detection-engine",
							Image: detectionImage,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1000m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
							},
							Ports: []corev1.ContainerPort{
								{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
								{Name: "mgmt", ContainerPort: 8081, Protocol: corev1.ProtocolTCP},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "ringbuf",
									MountPath: ringBufferMountPath,
								},
								{
									Name:      "evidence",
									MountPath: "/var/guardian/evidence",
								},
							},
							Env: buildDetectionEnv(policy),
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/actuator/health/liveness",
										Port: intstrVal(8081),
									},
								},
								InitialDelaySeconds: 30,
								PeriodSeconds:       10,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/actuator/health/readiness",
										Port: intstrVal(8081),
									},
								},
								InitialDelaySeconds: 15,
								PeriodSeconds:       5,
							},
							StartupProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/actuator/health",
										Port: intstrVal(8081),
									},
								},
								InitialDelaySeconds: 10,
								PeriodSeconds:       5,
								FailureThreshold:    12,
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "ringbuf",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium:    corev1.StorageMediumMemory,
									SizeLimit: resourcePtr(resource.MustParse("20Mi")),
								},
							},
						},
						{
							Name: "sys-kernel-debug",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/sys/kernel/debug",
								},
							},
						},
						{
							Name: "proc",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/proc",
								},
							},
						},
						{
							Name: "evidence",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									SizeLimit: resourcePtr(resource.MustParse("500Mi")),
								},
							},
						},
					},
				},
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: intstrPtr(1),
				},
			},
		},
	}

	return ds
}

func buildDetectionEnv(policy *guardianv1alpha1.GuardianPolicy) []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{
			Name:  "GUARDIAN_RINGBUFFER_PATH",
			Value: ringBufferMountPath + "/" + ringBufferFileName,
		},
		{
			Name:  "GUARDIAN_ACTION_DRY_RUN",
			Value: fmt.Sprintf("%t", policy.Spec.Response.DryRun),
		},
		{
			Name:  "GUARDIAN_ACTION_RATE_LIMIT_PER_MINUTE",
			Value: fmt.Sprintf("%d", policy.Spec.Response.RateLimitPerMinute),
		},
		{
			Name: "GUARDIAN_NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "spec.nodeName",
				},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
	}

	// Add threat intel secret refs
	if policy.Spec.ThreatIntel.VirusTotalSecretRef != nil {
		envs = append(envs, secretEnv("GUARDIAN_THREAT_INTEL_VIRUS_TOTAL_API_KEY",
			policy.Spec.ThreatIntel.VirusTotalSecretRef))
	}
	if policy.Spec.ThreatIntel.AbuseIPDBSecretRef != nil {
		envs = append(envs, secretEnv("GUARDIAN_THREAT_INTEL_ABUSE_IP_DB_API_KEY",
			policy.Spec.ThreatIntel.AbuseIPDBSecretRef))
	}
	if policy.Spec.ThreatIntel.OTXSecretRef != nil {
		envs = append(envs, secretEnv("GUARDIAN_THREAT_INTEL_OTX_API_KEY",
			policy.Spec.ThreatIntel.OTXSecretRef))
	}

	return envs
}

func secretEnv(envName string, ref *guardianv1alpha1.SecretRef) corev1.EnvVar {
	return corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: ref.Name},
				Key:                  ref.Key,
			},
		},
	}
}

func daemonSetName(policy *guardianv1alpha1.GuardianPolicy) string {
	return "guardian-monitor-" + policy.Name
}

func intstrVal(val int32) intstr.IntOrString {
	return intstr.FromInt32(val)
}

func intstrPtr(val int) *intstr.IntOrString {
	v := intstr.FromInt32(int32(val))
	return &v
}

func resourcePtr(r resource.Quantity) *resource.Quantity {
	return &r
}
