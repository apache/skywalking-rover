// Licensed to Apache Software Foundation (ASF) under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Apache Software Foundation (ASF) licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package kubernetes

import (
	"context"
	"strings"

	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodContainer struct {
	// pod references
	Pod             *v1.Pod
	ContainerSpec   v1.Container
	ContainerStatus v1.ContainerStatus

	// the kubernetes resource registry
	registry *Registry
}

// AnalyzeContainers means query the containers by pod
func AnalyzeContainers(pod *v1.Pod, registry *Registry) []*PodContainer {
	containers := make([]*PodContainer, 0)
	// nolint
	for _, cs := range pod.Status.ContainerStatuses {
		// nolint
		for _, c := range pod.Spec.Containers {
			if c.Name != cs.Name {
				continue
			}

			containers = append(containers, &PodContainer{
				Pod:             pod,
				ContainerSpec:   c,
				ContainerStatus: cs,
				registry:        registry,
			})
		}
	}
	return containers
}

func (c *PodContainer) CGroupID() string {
	cgroupID := c.ContainerStatus.ContainerID
	// delete the container runtime prefix is the cgroupid
	cgroupID = strings.TrimPrefix(cgroupID, "containerd://")
	cgroupID = strings.TrimPrefix(cgroupID, "dockerd://")
	cgroupID = strings.TrimPrefix(cgroupID, "docker://")
	return cgroupID
}

func (c *PodContainer) ServiceName() string {
	return c.registry.FindServiceName(c.Pod.Namespace, c.Pod.Name)
}

// FindOwner means query the owner in the container, it would loop up with parent owner until empty
func (c *PodContainer) FindOwner(ctx context.Context, kindName string, k8sConfig *rest.Config) (*metav1.OwnerReference, error) {
	// find in cache result
	findedReferences := make([]metav1.OwnerReference, 0)
	if owner := c.findOwner(c.Pod.OwnerReferences, kindName); owner != nil {
		return owner, nil
	}
	findedReferences = append(findedReferences, c.Pod.OwnerReferences...)

	// found from owner
	for len(findedReferences) > 0 {
		current := findedReferences[0]
		findedReferences = findedReferences[1:]

		// must be a controller
		if c := current.Controller; c != nil && !*c {
			continue
		}

		// query reference data
		restClient, err := c.parseRestClientFromAPIVersion(k8sConfig, current.APIVersion)
		if err != nil {
			return nil, err
		}
		do := restClient.Get().Resource(current.Kind + "s").
			Name(current.Name).
			Namespace(c.Pod.Namespace).
			Do(ctx)
		if do.Error() != nil {
			return nil, do.Error()
		}
		data := &unstructured.Unstructured{}
		if err := do.Into(data); err != nil {
			return nil, err
		}

		// query parent references from current reference
		references := data.GetOwnerReferences()
		if owner := c.findOwner(references, kindName); owner != nil {
			return owner, nil
		}
		findedReferences = append(findedReferences, references...)
	}
	return nil, nil
}

func (c *PodContainer) FindContainerFromSamePod(name string) *PodContainer {
	cs := AnalyzeContainers(c.Pod, c.registry)
	for _, co := range cs {
		if co.ContainerSpec.Name == name {
			return co
		}
	}
	return nil
}

func (c *PodContainer) parseRestClientFromAPIVersion(conf *rest.Config, apiVersion string) (rest.Interface, error) {
	groupVersion, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, err
	}
	queryConf := rest.CopyConfig(conf)
	queryConf.GroupVersion = &groupVersion
	queryConf.APIPath = "/apis"
	queryConf.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	if queryConf.UserAgent == "" {
		queryConf.UserAgent = rest.DefaultKubernetesUserAgent()
	}
	return rest.RESTClientFor(queryConf)
}

func (c *PodContainer) findOwner(refs []metav1.OwnerReference, kindName string) *metav1.OwnerReference {
	for _, o := range refs {
		if o.Kind == kindName {
			return &o
		}
	}
	return nil
}
