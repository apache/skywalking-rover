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
	"time"

	"k8s.io/apimachinery/pkg/labels"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const rsyncPeriod = 5 * time.Minute

type Registry struct {
	podInformers     []cache.SharedInformer
	serviceInformers []cache.SharedInformer

	podServiceNameCache map[string]string
}

func NewRegistry(cli *kubernetes.Clientset, namespaces []string, nodeName string) *Registry {
	r := &Registry{
		podInformers:        make([]cache.SharedInformer, 0),
		serviceInformers:    make([]cache.SharedInformer, 0),
		podServiceNameCache: make(map[string]string),
	}
	for _, ns := range namespaces {
		podListWatch := cache.NewListWatchFromClient(cli.CoreV1().RESTClient(), "pods", ns, fields.OneTermEqualSelector("spec.nodeName", nodeName))
		podInformer := cache.NewSharedInformer(podListWatch, &v1.Pod{}, rsyncPeriod)
		podInformer.AddEventHandler(r)
		r.podInformers = append(r.podInformers, podInformer)

		serviceListWatch := cache.NewListWatchFromClient(cli.CoreV1().RESTClient(), "services", ns, fields.Everything())
		serviceInformer := cache.NewSharedInformer(serviceListWatch, &v1.Service{}, rsyncPeriod)
		serviceInformer.AddEventHandler(r)
		r.serviceInformers = append(r.serviceInformers, serviceInformer)
	}

	return r
}

func (r *Registry) Start(stopChan chan struct{}) {
	for i := range r.podInformers {
		go r.podInformers[i].Run(stopChan)
		go r.serviceInformers[i].Run(stopChan)
	}
}

func (r *Registry) BuildPodContainers() map[string]*PodContainer {
	// cgroupid -> container
	containers := make(map[string]*PodContainer)
	for _, in := range r.podInformers {
		list := in.GetStore().List()
		for _, p := range list {
			analyzeContainers := AnalyzeContainers(p.(*v1.Pod), r)
			for _, c := range analyzeContainers {
				id := c.CGroupID()
				if id != "" {
					containers[id] = c
				}
			}
		}
	}
	return containers
}

func (r *Registry) FindServiceName(namespace, podName string) string {
	return r.podServiceNameCache[namespace+"_"+podName]
}

func (r *Registry) recomposePodServiceName() {
	result := make(map[string]string)
	for i := range r.podInformers {
		for _, podT := range r.podInformers[i].GetStore().List() {
			for _, serviceT := range r.serviceInformers[i].GetStore().List() {
				pod := podT.(*v1.Pod)
				service := serviceT.(*v1.Service)

				if pod.Namespace != service.Namespace {
					continue
				}
				if len(service.Spec.Selector) == 0 {
					continue
				}

				if labels.Set(service.Spec.Selector).AsSelector().Matches(labels.Set(pod.ObjectMeta.Labels)) {
					// if multiple service selector matches the same pod
					// then must choose one by same logical
					existing := result[pod.Namespace+"_"+pod.Name]
					if existing != "" {
						existing = chooseServiceName(existing, service.Name)
					} else {
						existing = service.Name
					}
					result[pod.Namespace+"_"+pod.Name] = existing
				}
			}
		}
	}
	r.podServiceNameCache = result
}

func chooseServiceName(a, b string) string {
	// short name
	if len(a) < len(b) {
		return a
	} else if len(a) > len(b) {
		return b
	}
	// ascii compare
	if a < b {
		return a
	}
	return b
}

func (r *Registry) OnAdd(_ interface{}) {
	r.recomposePodServiceName()
}

func (r *Registry) OnUpdate(_, _ interface{}) {
	r.recomposePodServiceName()
}

func (r *Registry) OnDelete(_ interface{}) {
	r.recomposePodServiceName()
}
