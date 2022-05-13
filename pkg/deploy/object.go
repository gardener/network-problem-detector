// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

type Object interface {
	runtime.Object
	metav1.Object
}

type buildObject[T Object] func() (T, error)

type ObjectInterface[T Object] interface {
	Create(ctx context.Context, obj T, opts metav1.CreateOptions) (T, error)
	Update(ctx context.Context, obj T, opts metav1.UpdateOptions) (T, error)
	Get(ctx context.Context, name string, opts metav1.GetOptions) (T, error)
}

type ObjectDelete interface {
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

func genericCreateOrUpdate(ctx context.Context, clientset *kubernetes.Clientset, object Object) (Object, error) {
	switch v := object.(type) {
	case *corev1.ConfigMap:
		return createOrUpdate(ctx, "configmap", clientset.CoreV1().ConfigMaps(object.GetNamespace()), v)
	case *corev1.Secret:
		return createOrUpdate(ctx, "secret", clientset.CoreV1().Secrets(object.GetNamespace()), v)
	case *corev1.Service:
		return createOrUpdate(ctx, "service", clientset.CoreV1().Services(object.GetNamespace()), v)
	case *corev1.ServiceAccount:
		return createOrUpdate(ctx, "serviceaccount", clientset.CoreV1().ServiceAccounts(object.GetNamespace()), v)
	case *appsv1.Deployment:
		return createOrUpdate(ctx, "deployment", clientset.AppsV1().Deployments(object.GetNamespace()), v)
	case *appsv1.DaemonSet:
		return createOrUpdate(ctx, "deployment", clientset.AppsV1().DaemonSets(object.GetNamespace()), v)
	case *rbacv1.ClusterRole:
		return createOrUpdate(ctx, "clusterrole", clientset.RbacV1().ClusterRoles(), v)
	case *rbacv1.ClusterRoleBinding:
		return createOrUpdate(ctx, "clusterrolebinding", clientset.RbacV1().ClusterRoleBindings(), v)
	case *rbacv1.Role:
		return createOrUpdate(ctx, "role", clientset.RbacV1().Roles(object.GetNamespace()), v)
	case *rbacv1.RoleBinding:
		return createOrUpdate(ctx, "rolebinding", clientset.RbacV1().RoleBindings(object.GetNamespace()), v)
	case *policyv1beta1.PodSecurityPolicy:
		return createOrUpdate(ctx, "podsecuritypolicy", clientset.PolicyV1beta1().PodSecurityPolicies(), v)
	default:
		return nil, fmt.Errorf("unsupported type: %T", v)
	}
}

func genericDeleteWithLog(ctx context.Context, log logrus.FieldLogger, clientset *kubernetes.Clientset, object Object) error {
	typename, namespaced := typename(object)
	err := genericDelete(ctx, clientset, object)
	if err != nil && errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	prefix := ""
	if namespaced {
		prefix = object.GetNamespace() + "/"
	}
	log.Infof("deleted %s %s%s", typename, prefix, object.GetName())
	return nil
}

func genericDelete(ctx context.Context, clientset *kubernetes.Clientset, object Object) error {
	var itf ObjectDelete
	switch v := object.(type) {
	case *corev1.ConfigMap:
		itf = clientset.CoreV1().ConfigMaps(object.GetNamespace())
	case *corev1.Secret:
		itf = clientset.CoreV1().Secrets(object.GetNamespace())
	case *corev1.Service:
		itf = clientset.CoreV1().Services(object.GetNamespace())
	case *corev1.ServiceAccount:
		itf = clientset.CoreV1().ServiceAccounts(object.GetNamespace())
	case *appsv1.Deployment:
		itf = clientset.AppsV1().Deployments(object.GetNamespace())
	case *appsv1.DaemonSet:
		itf = clientset.AppsV1().DaemonSets(object.GetNamespace())
	case *rbacv1.ClusterRole:
		itf = clientset.RbacV1().ClusterRoles()
	case *rbacv1.ClusterRoleBinding:
		itf = clientset.RbacV1().ClusterRoleBindings()
	case *rbacv1.Role:
		itf = clientset.RbacV1().Roles(object.GetNamespace())
	case *rbacv1.RoleBinding:
		itf = clientset.RbacV1().RoleBindings(object.GetNamespace())
	case *policyv1beta1.PodSecurityPolicy:
		itf = clientset.PolicyV1beta1().PodSecurityPolicies()
	default:
		return fmt.Errorf("unsupported type: %T", v)
	}
	return itf.Delete(ctx, object.GetName(), metav1.DeleteOptions{})
}

func typename(object Object) (string, bool) {
	switch v := object.(type) {
	case *corev1.ConfigMap:
		return "configmap", true
	case *corev1.Secret:
		return "secret", true
	case *corev1.Service:
		return "service", true
	case *corev1.ServiceAccount:
		return "serviceaccount", true
	case *appsv1.Deployment:
		return "deployment", true
	case *appsv1.DaemonSet:
		return "daemonset", true
	case *rbacv1.ClusterRole:
		return "clusterrole", false
	case *rbacv1.ClusterRoleBinding:
		return "clusterrolebinding", false
	case *rbacv1.Role:
		return "role", true
	case *rbacv1.RoleBinding:
		return "role", true
	case *policyv1beta1.PodSecurityPolicy:
		return "podsecuritypolicy", false
	default:
		return fmt.Sprintf("unsupported type: %T", v), false
	}
}

func createOrUpdate[T Object, S ObjectInterface[T]](ctx context.Context, typename string, itf S, obj T) (result T, err error) {
	op := "creating"
	result, err = itf.Create(ctx, obj, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		var old T
		old, err = itf.Get(ctx, obj.GetName(), metav1.GetOptions{})
		if err != nil {
			op = "getting"
		} else {
			op = "updating"
			obj.SetResourceVersion(old.GetResourceVersion())
			result, err = itf.Update(ctx, obj, metav1.UpdateOptions{})
		}
	}
	if err != nil {
		err = fmt.Errorf("error %s %s %s/%s: %s", op, typename, obj.GetNamespace(), obj.GetName(), err)
	}
	return
}
