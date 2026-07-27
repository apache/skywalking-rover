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

package ztunnel

import (
	"fmt"

	"github.com/apache/skywalking-rover/pkg/tools/elf"
)

// ReadELFBuildID returns the hex-encoded GNU build ID of a ztunnel binary.
//
// The build ID is the ONLY sound key for a pre-generated offset table. A ztunnel version string
// is not: the ztunnel shipped by a distribution can carry a version label whose code is nothing
// like the upstream release of the same number - measured on a live cluster, an image labeled
// "1.28.3" contained `ConnectionResultBuilder`(an upstream 1.29+ API) and the
// `src.cluster`/`dst.cluster` access-log fields(upstream 1.31+), plus vendor-only patches.
// Looking up offsets by that label would read the wrong bytes out of a differently-laid-out
// struct, so matching is done on the exact binary identity instead and the version string is
// kept for diagnostics only.
func ReadELFBuildID(path string) (string, error) {
	file, err := elf.NewFile(path)
	if err != nil {
		return "", fmt.Errorf("open elf %s error: %w", path, err)
	}
	defer file.Close()
	return file.BuildID()
}
