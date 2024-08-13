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
	"regexp"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"

	commonv3 "skywalking.apache.org/repo/goapi/collect/common/v3"

	"github.com/shirou/gopsutil/process"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/process/v3"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

var log = logger.GetLogger("process", "finder", "kubernetes")

var kubepodsRegex = regexp.MustCompile(`cri-containerd-(?P<Group>\w+)\.scope`)

type ProcessFinder struct {
	conf *Config

	// runtime
	clusterName  string
	manager      base.ProcessManager
	ctx          context.Context
	cancelCtx    context.CancelFunc
	stopChan     chan struct{}
	processCache *lru.Cache

	// k8s clients
	k8sConfig *rest.Config
	registry  *Registry
	CLI       *kubernetes.Clientset

	// runtime config
	namespaces []string
}

func (f *ProcessFinder) Init(ctx context.Context, conf base.FinderBaseConfig, manager base.ProcessManager) error {
	f.clusterName = manager.GetModuleManager().FindModule(core.ModuleName).(core.Operator).ClusterName()
	k8sConf, cli, err := f.validateConfig(ctx, conf.(*Config))
	if err != nil {
		return err
	}
	f.conf = conf.(*Config)
	f.k8sConfig = k8sConf
	f.CLI = cli

	f.ctx, f.cancelCtx = context.WithCancel(ctx)
	f.stopChan = make(chan struct{}, 1)
	f.registry = NewRegistry(f.CLI, f.namespaces, f.conf.NodeName)
	f.manager = manager
	cache, err := lru.New(5000)
	if err != nil {
		return err
	}
	f.processCache = cache

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
	if err := ProcessBuildersInit(conf.Analyzers); err != nil {
		return nil, nil, err
	}

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

	result := make([]api.DetectedProcess, 0)
	for _, p := range processes {
		result, _ = f.buildProcess(p, result, containers)
	}

	if len(result) > 0 {
		f.manager.SyncAllProcessInFinder(result)
	}
	return nil
}

func (f *ProcessFinder) buildProcess(p *process.Process, detectedProcesses []api.DetectedProcess,
	containers map[string]*PodContainer) ([]api.DetectedProcess, bool) {
	createTime, err := p.CreateTime()
	if err != nil {
		return detectedProcesses, false
	}
	processCahceKey := fmt.Sprintf("%d_%d", p.Pid, createTime)
	cachedProcesses, exist := f.processCache.Get(processCahceKey)
	if exist {
		for _, pro := range cachedProcesses.([]*Process) {
			detectedProcesses = append(detectedProcesses, pro)
		}
		return detectedProcesses, true
	}

	cgroups, err := f.getProcessCGroup(p.Pid)
	if err != nil {
		return detectedProcesses, false
	}

	var c *PodContainer
	for _, cgroup := range cgroups {
		if cc := containers[cgroup]; cc != nil {
			c = cc
			break
		}
	}
	if c == nil {
		return detectedProcesses, false
	}

	// find process builder
	ps, err := f.buildProcesses(p, c)
	if err != nil {
		log.Warnf("find process builder error for pid: %d, err: %v", p.Pid, err)
		return detectedProcesses, false
	}

	for _, pro := range ps {
		detectedProcesses = append(detectedProcesses, pro)
	}
	f.processCache.Add(processCahceKey, ps)
	return detectedProcesses, true
}

func (f *ProcessFinder) buildProcesses(p *process.Process, pc *PodContainer) ([]*Process, error) {
	// find builder
	builders := make([]*ProcessBuilder, 0)
	for _, b := range f.conf.Analyzers {
		if !b.Active {
			continue
		}
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
		// adding the cluster name into the service name
		if f.clusterName != "" && !strings.Contains(entity.ServiceName, "::") {
			entity.ServiceName = fmt.Sprintf("%s::%s", f.clusterName, entity.ServiceName)
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

func (f *ProcessFinder) getProcessCGroup(pid int32) ([]string, error) {
	processCgroupFilePath := host.GetFileInHost(fmt.Sprintf("/proc/%d/cgroup", pid))
	cgroupFile, err := os.Open(processCgroupFilePath)
	if err != nil {
		return nil, err
	}
	defer cgroupFile.Close()

	cache := make(map[string]bool)
	scanner := bufio.NewScanner(cgroupFile)
	for scanner.Scan() {
		infos := strings.Split(scanner.Text(), ":")
		if len(infos) < 3 {
			continue
		}
		lastPath := strings.LastIndex(infos[2], "/")
		if lastPath > 1 && lastPath != len(infos[2])-1 {
			path := infos[2][lastPath+1:]
			// adapt Kubepod
			// ex: cri-containerd-7dae778c37bd1204677518f1032bbecf01f5c41878ea7bd370021263417cc626.scope
			if kubepod := kubepodsRegex.FindStringSubmatch(path); len(kubepod) >= 1 {
				path = kubepod[1]
			}
			cache[path] = true
		}
	}
	if len(cache) == 0 {
		return nil, fmt.Errorf("no cgroups")
	}
	result := make([]string, 0)
	for k := range cache {
		result = append(result, k)
	}
	return result, nil
}

func (f *ProcessFinder) Stop() error {
	close(f.stopChan)
	f.cancelCtx()
	return nil
}

func (f *ProcessFinder) DetectType() api.ProcessDetectType {
	return api.Kubernetes
}

func (f *ProcessFinder) ValidateProcessIsSame(p1, p2 api.DetectedProcess) bool {
	k1 := p1.(*Process)
	k2 := p2.(*Process)
	return p1.Pid() == p2.Pid() && k1.cmd == k2.cmd && p1.Entity().SameWith(p2.Entity())
}

func (f *ProcessFinder) BuildNecessaryProperties(ps api.DetectedProcess) []*commonv3.KeyStringValuePair {
	return []*commonv3.KeyStringValuePair{
		{
			Key:   "support_ebpf_profiling",
			Value: strconv.FormatBool(ps.ProfilingStat() != nil),
		},
	}
}

func (f *ProcessFinder) BuildEBPFProcess(ctx *base.BuildEBPFProcessContext, ps api.DetectedProcess) *v3.EBPFProcessProperties {
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
			Key:   "container_name",
			Value: ps.(*Process).podContainer.ContainerSpec.Name,
		},
		{
			Key:   "pod_name",
			Value: ps.(*Process).podContainer.Pod.Name,
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
	k8sProcess.Properties = append(k8sProcess.Properties, f.BuildNecessaryProperties(ps)...)
	properties := &v3.EBPFProcessProperties{Metadata: &v3.EBPFProcessProperties_K8SProcess{
		K8SProcess: k8sProcess,
	}}
	return properties
}

func (f *ProcessFinder) ParseProcessID(ps api.DetectedProcess, downstream *v3.EBPFProcessDownstream) string {
	if downstream.GetK8SProcess() == nil {
		return ""
	}
	if ps.Pid() == downstream.GetK8SProcess().GetPid() &&
		base.EntityIsSameWithProtocol(ps.Entity(), downstream.GetK8SProcess().GetEntityMetadata()) {
		return downstream.GetProcessId()
	}
	return ""
}

func (f *ProcessFinder) ShouldMonitor(pid int32) bool {
	newProcess, err := process.NewProcess(pid)
	if err != nil {
		return false
	}
	// analyze the process needs to be monitored
	processes, monitor := f.buildProcess(newProcess, nil, f.registry.BuildPodContainers())
	if !monitor || len(processes) == 0 {
		return false
	}
	f.manager.AddDetectedProcess(processes)
	return true
}
