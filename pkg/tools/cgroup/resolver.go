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

// Package cgroup resolves the cgroup ids that eBPF programs report(through
// bpf_get_current_cgroup_id) to the container they belong to, and back.
package cgroup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/host"
)

var log = logger.GetLogger("tools", "cgroup")

// DefaultMountPoint is where the unified(v2) cgroup hierarchy lives, as seen from inside the agent
// container.
//
// It has to be the *host's* /sys: the agent's own only exposes its own cgroup subtree, and the
// containers whose ids we need are not in it. Where the host's /sys is mounted is a property of the
// deployment - the helm chart bind-mounts it at /sys, an environment where the node is itself a
// container may put it elsewhere - so the prefix comes from ROVER_HOST_SYS_MAPPING rather than
// being assumed, exactly as the /proc prefix does.
func DefaultMountPoint() string {
	return host.GetHostSysInHost("fs/cgroup")
}

const (
	// controllersFile only exists on the unified(v2) hierarchy, which makes its presence the
	// probe for "this host runs cgroup v2". On a v1-only host bpf_get_current_cgroup_id() reports
	// the id from the unified hierarchy, where the containers are not, so every lookup would miss
	// and the caller must disable the whole cgroup based path instead.
	controllersFile = "cgroup.controllers"
)

// There is deliberately no bound on how deep the walk goes, because there is no depth to bound it
// to. Where a container's cgroup sits is not fixed by anything:
//
//   - the cgroup driver decides both the naming and the number of levels(systemd:
//     kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<uid>.slice/<id>.scope, cgroupfs:
//     kubepods/<qos>/pod<uid>/<id>)
//   - the QoS class adds a level for burstable/besteffort that guaranteed pods do not have
//   - wherever the kubelet itself runs inside a container(kind, docker-in-docker) the whole
//     hierarchy hangs under that container's cgroup, e.g. /system.slice/docker-<node>.scope/
//     kubelet.slice/kubelet-kubepods.slice/..., which is three levels further down
//   - the kubelet can be pointed at an arbitrary cgroup root
//
// If the layout were knowable the path could simply be built and stat'ed, and none of this would
// exist. It is not, which is why the tree is walked and matched by name - so what makes a directory
// a container is its name, never how deep it happens to be. An earlier version guessed a depth that
// fit a bare node; on a nested one it matched nothing at all and did so silently.
//
// The walk itself is cheap: the tree holds at most a few thousand directories, only their names are
// read, and a directory is stat'ed only once its name says it is a container.

// NameNormalizer turns the base name of a cgroup directory into the id of the container it holds,
// or "" when the directory does not belong to a container. It is injected rather than implemented
// here because the naming is container runtime specific and the process finder already owns those
// rules.
type NameNormalizer func(dirName string) string

// Resolver maps cgroup ids to container ids and back, by walking the host's cgroup v2 tree.
//
// The kernel identifies a cgroup v2 by the inode of its directory, and that inode is precisely
// what bpf_get_current_cgroup_id() returns, so the mapping is built by stat'ing the tree.
//
// Reading the tree from the mounted cgroupfs - rather than from /proc/<pid>/cgroup - is the whole
// point: the paths in /proc/<pid>/cgroup are rendered relative to the cgroup namespace of the
// *reading* process, so an agent living in its own namespace reads unresolvable paths such as
// "0::/../<container-id>", whereas a bind-mounted host cgroupfs exposes the full tree with real
// inodes no matter which namespace the reader sits in.
type Resolver struct {
	mountPoint string
	normalize  NameNormalizer

	mu            sync.RWMutex
	idByContainer map[string]uint64
	containerByID map[uint64]string
}

// NewResolver builds a Resolver over mountPoint(use DefaultMountPoint unless testing). It does not
// walk anything yet; call Refresh for that.
func NewResolver(mountPoint string, normalize NameNormalizer) *Resolver {
	return &Resolver{
		mountPoint:    mountPoint,
		normalize:     normalize,
		idByContainer: make(map[string]uint64),
		containerByID: make(map[uint64]string),
	}
}

// Available reports whether mountPoint holds a usable unified(v2) hierarchy. A caller must treat a
// false here as "the cgroup id of a process cannot be resolved on this host" and fall back to
// whatever it did before, never as a reason to fail.
func Available(mountPoint string) bool {
	st, err := os.Stat(filepath.Join(mountPoint, controllersFile))
	return err == nil && !st.IsDir()
}

// Refresh rebuilds the mapping from the current state of the tree. It is meant to be driven by the
// periodic process discovery: a cgroup that appears between two refreshes is simply resolved on the
// next one, and until then the caller behaves as it did before this package existed.
func (r *Resolver) Refresh() error {
	idByContainer := make(map[string]uint64)
	containerByID := make(map[uint64]string)

	root := filepath.Clean(r.mountPoint)
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A cgroup that vanished mid-walk is normal churn on a busy node, so skip it. Anything
			// else - a permission or an IO error - must not be swallowed: it would leave the mapping
			// quietly incomplete, and an incomplete mapping does not look like a failure. It looks
			// exactly like the containers it missed having no short-lived processes. Fail instead,
			// so the caller keeps its previous mapping, or falls back, knowingly.
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if !d.IsDir() {
			return nil
		}
		scanned++
		container := r.normalize(d.Name())
		if container == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil //nolint:nilerr // the directory disappeared mid-walk
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		id := stat.Ino
		idByContainer[container] = id
		containerByID[id] = container
		// The path is logged with the id because this mapping is the one thing that has to agree
		// with what the kernel reports: bpf_get_current_cgroup_id() returns the inode of exactly
		// this directory. If the two ever disagree, the id and the path it was read from are what
		// is needed to see why.
		log.Debugf("cgroup mapping: id=%d container=%s path=%s",
			id, container, strings.TrimPrefix(path, root))
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking the cgroup tree at %s: %w", root, err)
	}
	log.Debugf("cgroup walk over %s finished: %d directories scanned, %d containers mapped",
		root, scanned, len(containerByID))

	r.mu.Lock()
	defer r.mu.Unlock()
	r.idByContainer = idByContainer
	r.containerByID = containerByID
	return nil
}

// CgroupIDByContainer returns the cgroup id of a container, for seeding the BPF allowlist.
func (r *Resolver) CgroupIDByContainer(containerID string) (uint64, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, exist := r.idByContainer[containerID]
	return id, exist
}

// ContainerByCgroupID returns the container a cgroup id belongs to. This is the direction that lets
// a process which has already exited still be attributed: the cgroup id arrives with the kernel
// event, so nothing has to be read from the process's /proc entry.
func (r *Resolver) ContainerByCgroupID(id uint64) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	container, exist := r.containerByID[id]
	return container, exist
}

// Size reports how many container cgroups are currently mapped, for logging.
func (r *Resolver) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.containerByID)
}
