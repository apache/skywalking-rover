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
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	commonv3 "skywalking.apache.org/repo/goapi/collect/common/v3"

	"github.com/shirou/gopsutil/process"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/process/v3"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

var log = logger.GetLogger("process", "finder", "kubernetes")

type ProcessFinder struct {
	conf *Config

	// runtime
	manager   base.ProcessManager
	ctx       context.Context
	cancelCtx context.CancelFunc
	stopChan  chan struct{}

	// k8s clients
	k8sConfig *rest.Config
	cli       *kubernetes.Clientset
	registry  *Registry

	// runtime config
	namespaces      []string
	processBuilders []*ProcessBuilder
}

func (f *ProcessFinder) Init(ctx context.Context, conf base.FinderBaseConfig, manager base.ProcessManager) error {
	k8sConf, cli, err := f.validateConfig(ctx, conf.(*Config))
	if err != nil {
		return err
	}
	f.conf = conf.(*Config)
	f.k8sConfig = k8sConf
	f.cli = cli

	f.ctx, f.cancelCtx = context.WithCancel(ctx)
	f.stopChan = make(chan struct{}, 1)
	f.registry = NewRegistry(f.cli, f.namespaces, f.conf.NodeName)
	f.manager = manager

	return nil
}

func (f *ProcessFinder) validateConfig(ctx context.Context, conf *Config) (*rest.Config, *kubernetes.Clientset, error) {
	// init kubernetes client, must be inside kubernetes cluster
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("please make sure started inside the kubernetes cluster: %v", err)
	}
	cli, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, nil, err
	}

	// check node exists
	_, err = cli.CoreV1().Nodes().Get(ctx, conf.NodeName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("could not found the node: %s, %v", conf.NodeName, err)
	}

	// namespace update
	if conf.Namespaces != "" {
		f.namespaces = strings.Split(conf.Namespaces, ",")
	} else {
		f.namespaces = []string{v1.NamespaceAll}
	}

	// process builders
	if conf.Activated == "" {
		return nil, nil, fmt.Errorf("please provide at least one feature")
	}
	features := strings.Split(conf.Activated, ",")
	processBuilders := make([]*ProcessBuilder, 0)
	for _, f := range features {
		builders, err := FeatureToProcessBuildersAndInit(f, conf)
		if err != nil {
			return nil, nil, err
		}
		processBuilders = append(processBuilders, builders...)
	}
	f.processBuilders = processBuilders

	return k8sConfig, cli, nil
}

func (f *ProcessFinder) Start() {
	// add service and pod informers
	f.registry.Start(f.stopChan)
	go func() {
		timeTicker := time.NewTicker(time.Second * 5)
		for {
			select {
			case <-timeTicker.C:
				if err := f.analyzeProcesses(); err != nil {
					log.Errorf("found process failure: %v", err)
				}
			case <-f.ctx.Done():
				timeTicker.Stop()
				return
			}
		}
	}()
}

func (f *ProcessFinder) analyzeProcesses() error {
	// find out all containers
	containers := f.registry.BuildPodContainers()
	if len(containers) == 0 {
		return nil
	}

	processes, err := process.Processes()
	if err != nil {
		return err
	}

	result := make([]base.DetectedProcess, 0)
	for _, p := range processes {
		cgroup, err := f.getProcessCGroup(p.Pid)
		if err != nil {
			continue
		}

		c := containers[cgroup]
		if c == nil {
			continue
		}

		// check support profiling
		_, err = base.BuildProfilingStat(p)
		if err != nil {
			continue
		}

		// find process builder
		ps, err := f.buildProcesses(p, c)
		if err != nil {
			log.Warnf("find process builder error for pid: %d, err: %v", p.Pid, err)
			continue
		}

		for _, pro := range ps {
			result = append(result, pro)
		}
	}

	if len(result) > 0 {
		f.manager.SyncAllProcessInFinder(result)
	}
	return nil
}

func (f *ProcessFinder) buildProcesses(p *process.Process, pc *PodContainer) ([]*Process, error) {
	// find builder
	builders := make([]*ProcessBuilder, 0)
	for _, b := range f.processBuilders {
		success, err := executeFilter(b.FiltersBuilder, p, pc, f)
		if err != nil {
			return nil, err
		} else if success {
			builders = append(builders, b)
		}
	}
	if len(builders) == 0 {
		return nil, nil
	}

	cmdline, err := p.Cmdline()
	if err != nil {
		return nil, err
	}

	// build process
	processes := make([]*Process, 0)
	for _, builder := range builders {
		entity := &api.ProcessEntity{}
		entity.Layer = builder.Layer
		entity.ServiceName, err = f.buildEntity(err, p, pc, builder.ServiceNameBuilder)
		entity.InstanceName, err = f.buildEntity(err, p, pc, builder.InstanceNameBuilder)
		entity.ProcessName, err = f.buildEntity(err, p, pc, builder.ProcessNameBuilder)
		entity.Labels = builder.Labels
		if err != nil {
			return nil, err
		}
		processes = append(processes, NewProcess(p, cmdline, pc, entity))
	}

	return processes, nil
}

func (f *ProcessFinder) buildEntity(err error, ps *process.Process, pc *PodContainer, entity *base.TemplateBuilder) (string, error) {
	if err != nil {
		return "", err
	}
	return renderTemplate(entity, ps, pc, f)
}

func (f *ProcessFinder) getProcessCGroup(pid int32) (string, error) {
	processCgroupFilePath := host.GetFileInHost(fmt.Sprintf("/proc/%d/cgroup", pid))
	cgroupFile, err := os.Open(processCgroupFilePath)
	if err != nil {
		return "", err
	}
	defer cgroupFile.Close()

	scanner := bufio.NewScanner(cgroupFile)
	for scanner.Scan() {
		infos := strings.Split(scanner.Text(), ":")
		if len(infos) < 3 {
			continue
		}
		// find by most common type of cgroup
		if infos[1] == "memory" {
			lastPath := strings.LastIndex(infos[2], "/")
			if lastPath > 1 && lastPath != len(infos[2])-1 {
				return infos[2][lastPath+1:], nil
			}
			return "", nil
		}
	}
	return "", fmt.Errorf("no memory config")
}

func (f *ProcessFinder) Stop() error {
	close(f.stopChan)
	f.cancelCtx()
	return nil
}

func (f *ProcessFinder) DetectType() api.ProcessDetectType {
	return api.Kubernetes
}

func (f *ProcessFinder) ValidateProcessIsSame(p1, p2 base.DetectedProcess) bool {
	k1 := p1.(*Process)
	k2 := p2.(*Process)
	return p1.Pid() == p2.Pid() && k1.cmd == k2.cmd && p1.Entity().SameWith(p2.Entity())
}

func (f *ProcessFinder) BuildEBPFProcess(ctx *base.BuildEBPFProcessContext, ps base.DetectedProcess) *v3.EBPFProcessProperties {
	k8sProcess := &v3.EBPFKubernetesProcessMetadata{}
	k8sProcess.Pid = ps.Pid()
	k8sProcess.Entity = &v3.EBPFProcessEntityMetadata{
		Layer:        ps.Entity().Layer,
		ServiceName:  ps.Entity().ServiceName,
		InstanceName: ps.Entity().InstanceName,
		ProcessName:  ps.Entity().ProcessName,
		Labels:       ps.Entity().Labels,
	}
	k8sProcess.Properties = []*commonv3.KeyStringValuePair{
		{
			Key:   "host_ip",
			Value: ctx.HostIP,
		},
		{
			Key:   "container_ip",
			Value: ps.(*Process).podContainer.Pod.Status.PodIP,
		},
		{
			Key:   "pid",
			Value: strconv.FormatInt(int64(ps.Pid()), 10),
		},
		{
			Key:   "command_line",
			Value: ps.(*Process).cmd,
		},
	}
	properties := &v3.EBPFProcessProperties{Metadata: &v3.EBPFProcessProperties_K8SProcess{
		K8SProcess: k8sProcess,
	}}
	return properties
}

func (f *ProcessFinder) ParseProcessID(ps base.DetectedProcess, downstream *v3.EBPFProcessDownstream) string {
	if downstream.GetK8SProcess() == nil {
		return ""
	}
	if ps.Pid() == downstream.GetK8SProcess().GetPid() {
		return downstream.GetProcessId()
	}
	return ""
}
