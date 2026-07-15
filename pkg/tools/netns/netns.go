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
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// RunInNetNS executes fn with the current OS thread switched into the network
// namespace referenced by netnsPath(e.g. /proc/<pid>/ns/net), and restores the
// original network namespace afterwards.
//
// Requires CAP_SYS_ADMIN. Everything that must happen inside the target
// namespace(creating sockets, dialing, reading responses) should be done
// inside fn, since only the calling OS thread is switched.
//
// Failure contract: if switching BACK to the original namespace fails, RunInNetNS
// returns the error but deliberately does NOT unlock the OS thread - it leaves the
// goroutine locked to that thread so the Go runtime destroys the thread(instead of
// reusing it for other goroutines) while it is still in the target namespace. The
// caller MUST therefore treat a restore error as terminal for the goroutine and
// return/exit promptly, doing no further work that could run in the wrong namespace.
// Run RunInNetNS from a dedicated, short-lived goroutine so a poisoned thread is
// discarded when that goroutine exits.
func RunInNetNS(netnsPath string, fn func() error) error {
	target, err := os.Open(netnsPath)
	if err != nil {
		return fmt.Errorf("open target netns %s error: %w", netnsPath, err)
	}
	defer target.Close()

	runtime.LockOSThread()
	// NOTE: open through the container's own procfs instead of the host proc mapping:
	// thread-self is a kernel magic symlink which always resolves to the calling thread
	// itself on any procfs instance, the host proc mapping is only required when
	// accessing OTHER processes' entries
	origin, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("open current netns error: %w", err)
	}
	defer origin.Close()

	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("enter netns %s error: %w", netnsPath, err)
	}

	fnErr := fn()

	if err := unix.Setns(int(origin.Fd()), unix.CLONE_NEWNET); err != nil {
		// cannot switch back to the original namespace, keep the thread locked
		// so the runtime destroys it instead of reusing it for other goroutines
		return fmt.Errorf("restore original netns error: %v, fn error: %v", err, fnErr)
	}
	runtime.UnlockOSThread()
	return fnErr
}
