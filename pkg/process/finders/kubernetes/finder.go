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
	"hash/fnv"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"

	commonv3 "skywalking.apache.org/repo/goapi/collect/common/v3"

	"github.com/shirou/gopsutil/process"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/util/rand"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/process/v3"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/process/finders/base"
	"github.com/apache/skywalking-rover/pkg/tools/cgroup"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

var log = logger.GetLogger("process", "finder", "kubernetes")

var (
	kubepodsRegex      = regexp.MustCompile(`cri-containerd-(?P<Group>\w+)\.scope`)
	openShiftPodsRegex = regexp.MustCompile(`crio-(?P<Group>\w+)\.scope`)
	dockerPodsRegex    = regexp.MustCompile(`docker-(?P<Group>\w+)\.scope`)
	ipExistTimeout     = time.Minute * 10
	ipSearchParallel   = 10

	// containerScopeRegexes is built once rather than per call: containerIDFromCgroupDir is the
	// normalizer for a full cgroup tree walk, so a per-call slice would allocate once per directory.
	containerScopeRegexes = []*regexp.Regexp{kubepodsRegex, openShiftPodsRegex, dockerPodsRegex}
)

// containerIDFromCgroupDir turns the base name of a cgroup directory into the id of the container
// it holds, or "" when it holds none. It mirrors the naming GetProcessCGroup already parses out of
// /proc/<pid>/cgroup, so that a container resolved by walking the tree and one resolved by reading
// a process's cgroup line come out with the same id.
func containerIDFromCgroupDir(dirName string) string {
	for _, re := range containerScopeRegexes {
		if m := re.FindStringSubmatch(dirName); len(m) > 1 {
			return m[1]
		}
	}
	// the cgroupfs driver, unlike the systemd one, names the directory after the container id
	if isContainerID(dirName) {
		return dirName
	}
	return ""
}

// isContainerID reports whether a bare cgroup directory name is a container id, which keeps the
// host's own slices(system.slice, init.scope, ...) out of the mapping.
func isContainerID(name string) bool {
	if len(name) < 12 {
		return false
	}
	for _, c := range name {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type ProcessFinder struct {
	conf *Config

	// runtime
	clusterName  string
	manager      base.ProcessManager
	ctx          context.Context
	cancelCtx    context.CancelFunc
	stopChan     chan struct{}
	processCache *lru.Cache

	// cgroupResolver maps cgroup ids to containers; nil when the host has no usable cgroup v2 tree
	cgroupResolver *cgroup.Resolver

	// k8s clients
	k8sConfig *rest.Config
	registry  Registry
	CLI       *kubernetes.Clientset

	// for IsPodIP check
	podIPChecker *cache.Expiring
	podIPMutexes map[int]*sync.Mutex
}

func (f *ProcessFinder) Init(ctx context.Context, conf base.FinderBaseConfig, manager base.ProcessManager) error {
	return f.InitWithRegistry(ctx, conf, manager, func(clientset *kubernetes.Clientset) Registry {
		config := conf.(*Config)
		var namespaces []string
		// namespace update
		if config.Namespaces != "" {
			namespaces = strings.Split(config.Namespaces, ",")
		} else {
			namespaces = []string{v1.NamespaceAll}
		}
		return NewStaticNamespaceRegistry(clientset, namespaces, config.NodeName)
	})
}

func (f *ProcessFinder) InitWithRegistry(ctx context.Context, conf base.FinderBaseConfig, manager base.ProcessManager,
	registrySupplier func(*kubernetes.Clientset) Registry) error {
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
	f.registry = registrySupplier(cli)
	f.manager = manager
	f.podIPChecker = cache.NewExpiring()
	f.podIPMutexes = make(map[int]*sync.Mutex)
	for i := 0; i < ipSearchParallel; i++ {
		f.podIPMutexes[i] = &sync.Mutex{}
	}
	processCache, err := lru.New(5000)
	if err != nil {
		return err
	}
	f.processCache = processCache

	// The cgroup mapping is what lets an already-exited process still be attributed to its pod, and
	// what lets the access log module filter in kernel space. It needs a cgroup v2 tree; on a v1
	// host the finder simply keeps working the way it always has, through the periodic /proc scan.
	cgroupMountPoint := cgroup.DefaultMountPoint()
	if cgroup.Available(cgroupMountPoint) {
		f.cgroupResolver = cgroup.NewResolver(cgroupMountPoint, containerIDFromCgroupDir)
		if err := f.cgroupResolver.Refresh(); err != nil {
			log.Warnf("cannot read the cgroup tree at %s, falling back to process discovery alone: %v",
				cgroupMountPoint, err)
			f.cgroupResolver = nil
		} else {
			log.Infof("resolving containers by cgroup id, %d container cgroups mapped", f.cgroupResolver.Size())
		}
	} else {
		log.Infof("no cgroup v2 hierarchy at %s, containers will only be discovered by the periodic scan",
			cgroupMountPoint)
	}

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
	// keep the cgroup mapping in step with the containers that come and go on this node; this scan
	// reads /proc directly, so it can never be held back by a stale mapping
	f.RefreshCgroupResolver()

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

	cgroups, err := f.GetProcessCGroup(p.Pid)
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
	ps, err := f.BuildProcesses(p, c)
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

func (f *ProcessFinder) BuildProcesses(p *process.Process, pc *PodContainer) ([]*Process, error) {
	return f.BuildProcessesWithFallbackName(p, pc, "")
}

// BuildProcessesWithFallbackName is BuildProcesses for a process whose /proc entry may already be
// gone: fallbackName(the kernel task name) then stands in for the command line. Passing "" gives
// exactly the behavior of BuildProcesses.
func (f *ProcessFinder) BuildProcessesWithFallbackName(p *process.Process, pc *PodContainer,
	fallbackName string) ([]*Process, error) {
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
	if err != nil || cmdline == "" {
		// the process is gone(or is a zombie, which keeps a readable but empty cmdline); the
		// kernel task name is all that is left to identify it by
		if fallbackName == "" {
			if err != nil {
				return nil, fmt.Errorf("cannot read the command line of process %d: %w", p.Pid, err)
			}
			return nil, fmt.Errorf("the command line of process %d is empty", p.Pid)
		}
		cmdline = fallbackName
	}

	// build process
	processes := make([]*Process, 0)
	for _, builder := range builders {
		entity := &api.ProcessEntity{}
		entity.Layer = builder.Layer
		entity.ServiceName, err = f.buildEntity(nil, p, pc, builder.ServiceNameBuilder, fallbackName)
		entity.InstanceName, err = f.buildEntity(err, p, pc, builder.InstanceNameBuilder, fallbackName)
		entity.ProcessName, err = f.buildEntity(err, p, pc, builder.ProcessNameBuilder, fallbackName)
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

func (f *ProcessFinder) buildEntity(err error, ps *process.Process, pc *PodContainer, entity *base.TemplateBuilder,
	fallbackName string) (string, error) {
	if err != nil {
		return "", err
	}
	return renderTemplate(entity, ps, pc, f, fallbackName)
}

func (f *ProcessFinder) GetProcessCGroup(pid int32) ([]string, error) {
	processCgroupFilePath := host.GetHostProcInHost(fmt.Sprintf("%d/cgroup", pid))
	cgroupFile, err := os.Open(processCgroupFilePath)
	if err != nil {
		return nil, err
	}
	defer cgroupFile.Close()

	cgroups := make(map[string]bool)
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
			if openShiftPod := openShiftPodsRegex.FindStringSubmatch(path); len(openShiftPod) >= 1 {
				path = openShiftPod[1]
			}
			cgroups[path] = true
		}
	}
	if len(cgroups) == 0 {
		return nil, fmt.Errorf("no cgroups")
	}
	result := make([]string, 0)
	for k := range cgroups {
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
			Value: strconv.FormatBool(ps.SupportProfiling()),
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

// ShouldMonitorExecuting judges a process the kernel has just started.
//
// It prefers the ordinary /proc based path, which is richer and is exactly what the periodic scan
// does. Only when /proc has nothing left to say - the process already exited, which is the whole
// reason it is worth catching this early - does it fall back to what the kernel handed us: the
// cgroup id identifies the container, and the task name stands in for the command line.
// This runs once per process the kernel reports, so the pod/container map is built once and shared
// by both paths below. Calling ShouldMonitor here instead would rebuild it a second time for every
// event, and rebuilding means walking every pod of every informer - the kind of per-event cost that
// made these tracepoints too expensive to keep the last time round.
func (f *ProcessFinder) ShouldMonitorExecuting(exec *api.ProcessExecuteContext) bool {
	containers := f.registry.BuildPodContainers()
	if len(containers) == 0 {
		return false
	}

	// the ordinary path: the process is still alive, so /proc answers just as it does for the
	// periodic scan
	if alive, err := process.NewProcess(exec.Pid); err == nil {
		if processes, monitor := f.buildProcess(alive, nil, containers); monitor && len(processes) > 0 {
			f.manager.AddDetectedProcess(processes)
			return true
		}
	}

	if exec.CgroupID == 0 || f.cgroupResolver == nil {
		// no kernel side identity to fall back on(cgroup v1, or the tree could not be walked)
		return false
	}
	containerID, exist := f.cgroupResolver.ContainerByCgroupID(exec.CgroupID)
	if !exist {
		return false
	}
	pc, exist := containers[containerID]
	if !exist || pc == nil {
		return false
	}
	// the process is gone, so nothing can be read from /proc; a bare Process carries the pid, which
	// is all the entity building still needs from it.
	processes, err := f.BuildProcessesWithFallbackName(&process.Process{Pid: exec.Pid}, pc, exec.Comm)
	if err != nil || len(processes) == 0 {
		log.Debugf("cannot build the exited process %d in container %s: %v", exec.Pid, containerID, err)
		return false
	}
	detected := make([]api.DetectedProcess, 0, len(processes))
	for _, p := range processes {
		detected = append(detected, p)
	}
	f.manager.AddDetectedProcess(detected)
	return true
}

// RefreshCgroupResolver rebuilds the cgroup id -> container mapping. The caller drives it from the
// periodic scan, which reads /proc and is therefore never blocked by whatever the mapping says.
func (f *ProcessFinder) RefreshCgroupResolver() {
	if f.cgroupResolver == nil {
		return
	}
	if err := f.cgroupResolver.Refresh(); err != nil {
		log.Warnf("cannot refresh the cgroup mapping, already started short-lived processes may not "+
			"be attributed until the next refresh: %v", err)
	}
}

// CgroupResolvable reports whether this host lets cgroup ids be resolved at all, which decides
// whether a caller may filter by cgroup or has to filter some other way.
func (f *ProcessFinder) CgroupResolvable() bool {
	return f.cgroupResolver != nil
}

// ContainerByCgroupID names the container a cgroup id belongs to. This is the direction that lets
// an already-exited process still be attributed: the cgroup id comes with the kernel event, so
// nothing has to be read from the process's /proc entry.
func (f *ProcessFinder) ContainerByCgroupID(cgroupID uint64) (string, bool) {
	if f.cgroupResolver == nil {
		return "", false
	}
	return f.cgroupResolver.ContainerByCgroupID(cgroupID)
}

// CgroupIDByContainer exposes the cgroup id of a container so the access log module can seed the
// kernel side allowlist with it. The second result is false when the container's cgroup is not(yet)
// mapped, which the caller must read as "cannot filter on this one", never as "monitor nothing".
func (f *ProcessFinder) CgroupIDByContainer(containerID string) (uint64, bool) {
	if f.cgroupResolver == nil {
		return 0, false
	}
	return f.cgroupResolver.CgroupIDByContainer(containerID)
}

func (f *ProcessFinder) IsPodIP(ip string) (bool, error) {
	val, exist := f.podIPChecker.Get(ip)
	if exist {
		return val.(bool), nil
	}

	// parallels the search
	h := fnv.New32a()
	h.Write([]byte(ip))
	sum32 := int(h.Sum32())
	mutex := f.podIPMutexes[sum32%ipSearchParallel]
	mutex.Lock()
	defer mutex.Unlock()

	pods, err := f.CLI.CoreV1().Pods(v1.NamespaceAll).List(f.ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("status.podIP", ip).String(),
		Limit:         1,
	})
	if err != nil {
		return false, err
	}
	found := len(pods.Items) > 0

	// the timeout added a random value to avoid the cache avalanche
	addedTime := time.Second * time.Duration(rand.IntnRange(10, 60))
	f.podIPChecker.Set(ip, found, ipExistTimeout+addedTime)
	return found, nil
}
