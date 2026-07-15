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

package netns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const currentThreadNetNSPath = "/proc/thread-self/ns/net"

func netnsInode(t *testing.T, path string) uint64 {
	t.Helper()
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s error: %v", path, err)
	}
	sys, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("unexpected stat type for %s", path)
	}
	return sys.Ino
}

func TestRunInNetNSErrorPaths(t *testing.T) {
	invalidFile := filepath.Join(t.TempDir(), "not-a-netns")
	if err := os.WriteFile(invalidFile, []byte("test"), 0o600); err != nil {
		t.Fatalf("prepare the invalid target file error: %v", err)
	}
	cases := []struct {
		name   string
		target string
	}{
		{"target path does not exist", "/proc/not-exist-process/ns/net"},
		{"target is not a network namespace", invalidFile},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			executed := false
			err := RunInNetNS(tt.target, func() error {
				executed = true
				return nil
			})
			if err == nil {
				t.Fatalf("expected an error when %s", tt.name)
			}
			if executed {
				t.Fatalf("the fn must not run when entering the netns failed(%s)", tt.name)
			}
		})
	}
}

func TestRunInNetNSSameNamespace(t *testing.T) {
	// lock the thread so the baseline and the after-check read the same thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	originInode := netnsInode(t, currentThreadNetNSPath)

	executed := false
	err := RunInNetNS(currentThreadNetNSPath, func() error {
		executed = true
		if inode := netnsInode(t, currentThreadNetNSPath); inode != originInode {
			return fmt.Errorf("the fn is not running in the target netns, inode: %d, want: %d", inode, originInode)
		}
		return nil
	})
	if err != nil {
		// entering a netns(even the same one) requires CAP_SYS_ADMIN
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("requires CAP_SYS_ADMIN to run: %v", err)
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if !executed {
		t.Fatal("the fn is not executed")
	}
	if inode := netnsInode(t, currentThreadNetNSPath); inode != originInode {
		t.Fatalf("the original netns is not restored after RunInNetNS")
	}

	// the error of the fn should be propagated to the caller
	sentinel := errors.New("sentinel error")
	if err := RunInNetNS(currentThreadNetNSPath, func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("the fn error is not propagated, got: %v", err)
	}
}

// TestRunInNetNSEntersDistinctNamespace enters a genuinely DIFFERENT network
// namespace and asserts the inode observed inside fn changes(setns took effect)
// and reverts afterwards(restore took effect). Unlike the same-namespace case,
// this fails if setns or the restore were silently dropped.
func TestRunInNetNSEntersDistinctNamespace(t *testing.T) {
	// build a distinct netns on a dedicated OS thread and expose its procfs path;
	// the thread stays parked(via release) so the namespace is kept alive.
	type nsRef struct {
		path  string
		inode uint64
		err   error
	}
	ready := make(chan nsRef, 1)
	release := make(chan struct{})
	go func() {
		// permanently pin(and never unlock) this thread: after Unshare it lives in
		// the new netns and must be discarded, not reused by other goroutines.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ready <- nsRef{err: err}
			return
		}
		path := fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())
		stat, err := os.Stat(path)
		if err != nil {
			ready <- nsRef{err: err}
			return
		}
		ready <- nsRef{path: path, inode: stat.Sys().(*syscall.Stat_t).Ino}
		<-release
	}()
	ns := <-ready
	defer close(release)
	if ns.err != nil {
		if errors.Is(ns.err, syscall.EPERM) {
			t.Skipf("requires CAP_SYS_ADMIN to create a network namespace: %v", ns.err)
		}
		t.Fatalf("create a distinct netns error: %v", ns.err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	originInode := netnsInode(t, currentThreadNetNSPath)
	if originInode == ns.inode {
		t.Fatalf("the new namespace(inode %d) unexpectedly equals the origin", ns.inode)
	}

	err := RunInNetNS(ns.path, func() error {
		if inode := netnsInode(t, currentThreadNetNSPath); inode != ns.inode {
			return fmt.Errorf("fn is not running in the target netns, inode: %d, want: %d", inode, ns.inode)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("requires CAP_SYS_ADMIN to enter a netns: %v", err)
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if inode := netnsInode(t, currentThreadNetNSPath); inode != originInode {
		t.Fatalf("the original netns(inode %d) is not restored after RunInNetNS, got %d", originInode, inode)
	}
}
