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
	"regexp"
	"strings"
)

// BuildInfo is what `ztunnel version` reports about itself.
//
// Only Version and GitRevision are ever matched against. IstioVersion deliberately is NOT:
// measured across real images it is inconsistent to the point of uselessness - upstream
// istio/ztunnel:1.26.0 reports "unknown", upstream 1.28.3 reports "1.28.3", and a vendor rebuild
// labeled 1.28.3 reports "unknown" - because it is sourced from an ISTIO_META_ISTIO_VERSION
// environment variable that a deployment may simply not set. The istio release number belongs to
// the offline generator, which knows which tag it built, not to runtime identification.
type BuildInfo struct {
	Version     string
	GitRevision string
	// BuildStatus is "Clean" for a build made from an unmodified checkout. Anything else means
	// the revision does not identify the source, so the revision cannot be used as a key.
	BuildStatus  string
	IstioVersion string
	RustVersion  string
}

// the field names ztunnel's `version` output prints, kept as named constants so the same labels
// used by the parser tests are not duplicated string literals.
const (
	buildInfoFieldVersion      = "Version"
	buildInfoFieldGitRevision  = "GitRevision"
	buildInfoFieldBuildStatus  = "BuildStatus"
	buildInfoFieldIstioVersion = "IstioVersion"
	buildInfoFieldRustVersion  = "RustVersion"
	// buildInfoUnknown is what String() renders for a nil/empty build info.
	buildInfoUnknown = "unknown"
)

// buildInfoField pulls `Name:"value"` out of the single-line Go-style struct dump ztunnel prints.
var buildInfoField = regexp.MustCompile(`(\w+):"([^"]*)"`)

// ParseBuildInfo decodes the line `ztunnel version` prints, e.g.
//
//	version.BuildInfo{Version:"8bda303…", GitRevision:"8bda303…", BuildStatus:"Clean", …}
func ParseBuildInfo(output string) (*BuildInfo, error) {
	line := ""
	for _, candidate := range strings.Split(output, "\n") {
		if strings.Contains(candidate, "BuildInfo{") {
			line = candidate
			break
		}
	}
	if line == "" {
		return nil, fmt.Errorf("no BuildInfo line in the ztunnel version output")
	}

	info := &BuildInfo{}
	for _, match := range buildInfoField.FindAllStringSubmatch(line, -1) {
		switch match[1] {
		case buildInfoFieldVersion:
			info.Version = match[2]
		case buildInfoFieldGitRevision:
			info.GitRevision = match[2]
		case buildInfoFieldBuildStatus:
			info.BuildStatus = match[2]
		case buildInfoFieldIstioVersion:
			info.IstioVersion = match[2]
		case buildInfoFieldRustVersion:
			info.RustVersion = match[2]
		}
	}
	if info.Version == "" && info.GitRevision == "" {
		return nil, fmt.Errorf("the ztunnel version output carried neither Version nor GitRevision")
	}
	return info, nil
}

// String renders the build info for a log line, so an operator looking at "this binary is not in
// the table" can see what it actually is.
func (b *BuildInfo) String() string {
	if b == nil {
		return buildInfoUnknown
	}
	return fmt.Sprintf("version=%s gitRevision=%s buildStatus=%s istioVersion=%s rustVersion=%s",
		b.Version, b.GitRevision, b.BuildStatus, b.IstioVersion, b.RustVersion)
}

// buildStatusClean is the BuildStatus of a build made from an unmodified checkout.
const buildStatusClean = "Clean"

// MatchKeys returns the identifiers this build may be looked up by, or nothing when the build
// cannot be identified by revision at all.
//
// A build reporting anything other than a clean status - or a revision carrying the `-dirty`
// suffix ztunnel appends - is refused: its revision describes the commit it started from, not the
// tree it was compiled from, so any number of different binaries can report the same string. That
// is not hypothetical; the vendor ztunnel running in production reports
// `77374b17…-dirty` with BuildStatus "Modified". Matching it against an entry generated from the
// clean upstream revision would read a differently-laid-out struct at the wrong offsets.
func (b *BuildInfo) MatchKeys() []string {
	if b == nil || (b.BuildStatus != "" && b.BuildStatus != buildStatusClean) {
		return nil
	}
	var keys []string
	for _, candidate := range []string{b.Version, b.GitRevision} {
		if candidate == "" || strings.Contains(candidate, "-dirty") {
			continue
		}
		keys = append(keys, candidate)
	}
	return keys
}
