package controller

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	guardianv1alpha1 "github.com/naveed-gung/zero-day-guardian/guardian-operator/api/v1alpha1"
)

const (
	guardianFinalizer = "guardian.zerodayguardian.io/finalizer"
	requeueInterval   = 30 * time.Second
)

// GuardianPolicyReconciler reconciles a GuardianPolicy object.
type GuardianPolicyReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	DaemonSetManager *DaemonSetManager
}

// +kubebuilder:rbac:groups=guardian.zerodayguardian.io,resources=guardianpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=guardian.zerodayguardian.io,resources=guardianpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=guardian.zerodayguardian.io,resources=guardianpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods;secrets;configmaps;serviceaccounts;namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=patch;update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=get;list;watch

// Reconcile handles GuardianPolicy create/update/delete events.
func (r *GuardianPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the GuardianPolicy instance
	var policy guardianv1alpha1.GuardianPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("GuardianPolicy deleted", "name", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to fetch GuardianPolicy: %w", err)
	}

	// Handle deletion with finalizer
	if !policy.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&policy, guardianFinalizer) {
			logger.Info("Cleaning up Guardian resources", "policy", policy.Name)

			if err := r.DaemonSetManager.Delete(ctx, &policy); err != nil {
				logger.Error(err, "Failed to clean up DaemonSet")
				return ctrl.Result{RequeueAfter: 5 * time.Second}, err
			}

			controllerutil.RemoveFinalizer(&policy, guardianFinalizer)
			if err := r.Update(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(&policy, guardianFinalizer) {
		controllerutil.AddFinalizer(&policy, guardianFinalizer)
		if err := r.Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Reconcile the DaemonSet for eBPF monitor + detection engine
	nodeCount, err := r.DaemonSetManager.Reconcile(ctx, &policy)
	if err != nil {
		logger.Error(err, "DaemonSet reconciliation failed")
		r.setCondition(&policy, "Ready", metav1.ConditionFalse, "ReconcileError", err.Error())
		policy.Status.Phase = "Error"
		_ = r.Status().Update(ctx, &policy)
		return ctrl.Result{RequeueAfter: requeueInterval}, err
	}

	// Update status
	policy.Status.MonitoredNodes = nodeCount
	if policy.Spec.Detection.Enabled {
		policy.Status.Phase = "Running"
		r.setCondition(&policy, "Ready", metav1.ConditionTrue, "Reconciled",
			fmt.Sprintf("Monitoring %d nodes", nodeCount))
	} else {
		policy.Status.Phase = "Pending"
		r.setCondition(&policy, "Ready", metav1.ConditionFalse, "DetectionDisabled",
			"Detection is disabled in policy spec")
	}

	if err := r.Status().Update(ctx, &policy); err != nil {
		logger.Error(err, "Failed to update status")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, err
	}

	logger.Info("Reconciliation complete",
		"policy", policy.Name,
		"phase", policy.Status.Phase,
		"nodes", nodeCount)

	return ctrl.Result{RequeueAfter: requeueInterval}, nil
}

func (r *GuardianPolicyReconciler) setCondition(
	policy *guardianv1alpha1.GuardianPolicy,
	condType string,
	status metav1.ConditionStatus,
	reason, message string,
) {
	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *GuardianPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&guardianv1alpha1.GuardianPolicy{}).
		Owns(&appsv1.DaemonSet{}).
		Complete(r)
}
