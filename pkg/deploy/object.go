// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

func createOrUpdate[T Object, S ObjectInterface[T]](ctx context.Context, typename string, itf S, obj T) (result T, err error) {
	op := "creating"
	result, err = itf.Create(ctx, obj, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		op = "updating"
		var old T
		old, err = itf.Get(ctx, obj.GetName(), metav1.GetOptions{})
		if err != nil {
			op = "getting"
		} else {
			obj.SetResourceVersion(old.GetResourceVersion())
			result, err = itf.Update(ctx, obj, metav1.UpdateOptions{})
		}
	}
	if err != nil {
		err = fmt.Errorf("error %s %s %s/%s: %s", op, typename, obj.GetNamespace(), obj.GetName(), err)
	}
	return
}
