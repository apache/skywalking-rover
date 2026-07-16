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

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

// containerdScope mirrors the systemd-driver naming the Kubernetes finder already parses.
var containerdScope = regexp.MustCompile(`cri-containerd-(\w+)\.scope`)

// testNormalizer applies the same rules the Kubernetes finder uses: a systemd scope carries the
// container id inside its name, while the cgroupfs driver names the directory after the id itself.
func testNormalizer(dirName string) string {
	if m := containerdScope.FindStringSubmatch(dirName); len(m) > 1 {
		return m[1]
	}
	if len(dirName) == 64 && !strings.ContainsAny(dirName, ".-") {
		return dirName
	}
	return ""
}

// inodeOf reads the inode the kernel gave a directory. On a real cgroup v2 tree this is the value
// bpf_get_current_cgroup_id() reports, which is the equivalence the Resolver relies on.
func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no Stat_t for %s", path)
	}
	return stat.Ino
}

func mkdirAll(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(parts...)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	return path
}

// buildTree lays out a cgroup v2 tree shaped like a real node: the kubepods slices a container
// lives under, plus host slices that must never be mistaken for containers.
func buildTree(t *testing.T) (root, systemdContainer, cgroupfsContainer string) {
	t.Helper()
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, controllersFile), []byte("cpu memory\n"), 0o600); err != nil {
		t.Fatalf("write controllers: %v", err)
	}

	// systemd driver: kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope
	systemdContainer = strings.Repeat("a", 64)
	mkdirAll(t, root, "kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod1234.slice", "cri-containerd-"+systemdContainer+".scope")

	// cgroupfs driver: kubepods/besteffort/pod<uid>/<id>
	cgroupfsContainer = strings.Repeat("b", 64)
	mkdirAll(t, root, "kubepods", "besteffort", "pod5678", cgroupfsContainer)

	// host slices - these must not show up as containers
	mkdirAll(t, root, "system.slice", "kubelet.service")
	mkdirAll(t, root, "init.scope")
	return root, systemdContainer, cgroupfsContainer
}

func TestResolverMapsContainersToTheirCgroupInode(t *testing.T) {
	root, systemdContainer, cgroupfsContainer := buildTree(t)

	r := NewResolver(root, testNormalizer)
	if err := r.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// exactly the two containers, none of the host slices
	if got := r.Size(); got != 2 {
		t.Fatalf("expected 2 container cgroups, got %d", got)
	}

	cases := []struct {
		name      string
		container string
		dir       string
	}{
		{"systemd driver", systemdContainer, filepath.Join(root, "kubepods.slice", "kubepods-burstable.slice",
			"kubepods-burstable-pod1234.slice", "cri-containerd-"+systemdContainer+".scope")},
		{"cgroupfs driver", cgroupfsContainer, filepath.Join(root, "kubepods", "besteffort", "pod5678", cgroupfsContainer)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := inodeOf(t, c.dir)

			// forward: container -> cgroup id, which is what seeds the BPF allowlist
			id, exist := r.CgroupIDByContainer(c.container)
			if !exist {
				t.Fatalf("container %s not mapped", c.container)
			}
			if id != want {
				t.Fatalf("cgroup id = %d, want the directory inode %d", id, want)
			}

			// reverse: cgroup id -> container, which is what attributes an already-exited process
			container, exist := r.ContainerByCgroupID(want)
			if !exist {
				t.Fatalf("cgroup id %d not mapped back", want)
			}
			if container != c.container {
				t.Fatalf("container = %s, want %s", container, c.container)
			}
		})
	}
}

func TestResolverIgnoresHostSlices(t *testing.T) {
	root, _, _ := buildTree(t)
	r := NewResolver(root, testNormalizer)
	if err := r.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// a host slice's inode must not resolve to any container: this is what keeps kubelet and
	// friends out of the allowlist.
	hostInode := inodeOf(t, filepath.Join(root, "system.slice", "kubelet.service"))
	if container, exist := r.ContainerByCgroupID(hostInode); exist {
		t.Fatalf("host slice resolved to container %s", container)
	}
}

// TestResolverFindsNestedKubeletLayout is the regression guard for the layout that appears wherever
// the kubelet itself runs inside a container(kind, docker-in-docker): the pod cgroups hang under
// the node container's own cgroup, which puts a container seven levels down instead of four. A
// depth bound sized for a bare node maps nothing here, and the failure is silent - the mapping is
// simply empty, so nothing is ever attributed.
func TestResolverFindsNestedKubeletLayout(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, controllersFile), []byte("cpu memory\n"), 0o600); err != nil {
		t.Fatalf("write controllers: %v", err)
	}
	container := strings.Repeat("d", 64)
	dir := mkdirAll(t, root, "system.slice", "docker-"+strings.Repeat("e", 64)+".scope",
		"kubelet.slice", "kubelet-kubepods.slice", "kubelet-kubepods-burstable.slice",
		"kubelet-kubepods-burstable-pod6fc4a17a_9b0a_4ab4_833e_7004a16f89ce.slice",
		"cri-containerd-"+container+".scope")

	r := NewResolver(root, testNormalizer)
	if err := r.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	id, exist := r.CgroupIDByContainer(container)
	if !exist {
		t.Fatal("a container under a nested kubelet hierarchy must still be mapped")
	}
	if want := inodeOf(t, dir); id != want {
		t.Fatalf("cgroup id = %d, want the directory inode %d", id, want)
	}
}

// TestResolverIsIndifferentToDepth pins the invariant that replaced the old depth bound: what makes
// a directory a container is its name, never how deep it sits. There is no layout to bound the walk
// to - the driver, the QoS class and a containerised kubelet each move things around - so a resolver
// that stops at some depth maps nothing on the layouts it did not anticipate, silently.
func TestResolverIsIndifferentToDepth(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, controllersFile), []byte("cpu memory\n"), 0o600); err != nil {
		t.Fatalf("write controllers: %v", err)
	}
	// far deeper than any real hierarchy, to show the walk is not the thing deciding
	container := strings.Repeat("f", 64)
	parts := []string{root}
	for i := 0; i < 20; i++ {
		parts = append(parts, fmt.Sprintf("nest%d", i))
	}
	dir := mkdirAll(t, append(parts, "cri-containerd-"+container+".scope")...)

	r := NewResolver(root, testNormalizer)
	if err := r.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	id, exist := r.CgroupIDByContainer(container)
	if !exist {
		t.Fatal("a container must be mapped no matter how deep it sits")
	}
	if want := inodeOf(t, dir); id != want {
		t.Fatalf("cgroup id = %d, want the directory inode %d", id, want)
	}
}

// TestRefreshFailsOnUnreadableSubtree pins the difference between the two kinds of walk error.
//
// A cgroup vanishing mid-walk is routine and must be skipped. Anything else - here an unreadable
// directory - has to fail the refresh instead, because a mapping that is quietly missing entries is
// indistinguishable from those containers simply having no short-lived processes: nothing errors,
// nothing is attributed, and there is no signal anywhere. Failing lets the caller keep its previous
// mapping, or fall back, knowing that it did.
func TestRefreshFailsOnUnreadableSubtree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the error cannot be provoked")
	}
	root, _, _ := buildTree(t)
	locked := mkdirAll(t, root, "kubepods.slice", "locked.slice")
	mkdirAll(t, locked, "cri-containerd-"+strings.Repeat("9", 64)+".scope")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// restored so t.TempDir can clean the tree up
	t.Cleanup(func() { os.Chmod(locked, 0o755) }) //nolint:errcheck // best effort

	r := NewResolver(root, testNormalizer)
	err := r.Refresh()
	if err == nil {
		t.Fatal("an unreadable subtree must fail the refresh, not silently shrink the mapping")
	}
	if !strings.Contains(err.Error(), "locked.slice") {
		t.Fatalf("the error should name the path it could not read, got: %v", err)
	}
}

// TestRefreshKeepsPreviousMappingOnFailure guards what a failed refresh must NOT do: throw away a
// mapping that was good. The periodic refresh only logs its error, so if a failure emptied the
// mapping the agent would stop attributing anything until some later walk happened to succeed.
func TestRefreshKeepsPreviousMappingOnFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the error cannot be provoked")
	}
	root, systemdContainer, _ := buildTree(t)
	r := NewResolver(root, testNormalizer)
	if err := r.Refresh(); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	before, exist := r.CgroupIDByContainer(systemdContainer)
	if !exist {
		t.Fatal("the container should be mapped after a good refresh")
	}

	locked := mkdirAll(t, root, "kubepods.slice", "locked2.slice")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) }) //nolint:errcheck // best effort

	if err := r.Refresh(); err == nil {
		t.Fatal("expected the refresh to fail")
	}
	after, exist := r.CgroupIDByContainer(systemdContainer)
	if !exist || after != before {
		t.Fatalf("a failed refresh must leave the previous mapping intact, got exist=%v id=%d want id=%d",
			exist, after, before)
	}
}

func TestAvailableProbesUnifiedHierarchy(t *testing.T) {
	root, _, _ := buildTree(t)
	if !Available(root) {
		t.Fatal("a tree with cgroup.controllers must be reported available")
	}

	// a v1 tree has no cgroup.controllers at its root, and there the cgroup id reported by BPF
	// would never match anything, so the caller must fall back instead.
	v1 := t.TempDir()
	mkdirAll(t, v1, "memory")
	if Available(v1) {
		t.Fatal("a tree without cgroup.controllers must not be reported available")
	}
}

// TestRefreshReplacesPreviousState makes sure a container that goes away stops resolving, rather
// than lingering and attributing a future process to a dead pod.
func TestRefreshReplacesPreviousState(t *testing.T) {
	root, systemdContainer, _ := buildTree(t)
	r := NewResolver(root, testNormalizer)
	if err := r.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, exist := r.CgroupIDByContainer(systemdContainer); !exist {
		t.Fatal("container should be mapped before removal")
	}

	if err := os.RemoveAll(filepath.Join(root, "kubepods.slice")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := r.Refresh(); err != nil {
		t.Fatalf("refresh after removal: %v", err)
	}
	if _, exist := r.CgroupIDByContainer(systemdContainer); exist {
		t.Fatal("a removed container must stop resolving after a refresh")
	}
}
