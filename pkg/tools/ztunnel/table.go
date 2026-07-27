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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/apache/skywalking-rover/pkg/logger"
)

// log carries the offset-table plumbing's diagnostics. The fallback ladder itself is logged by
// the collector that walks it; what is logged here is the one decision the ladder cannot see -
// how the active table was composed from the chained sources, and whether an override actually
// took effect. It is Debug because on a healthy node the built-in table simply answers and there
// is nothing to say; it becomes interesting only when an operator is chasing why their mounted or
// injected table did or did not change the outcome.
var log = logger.GetLogger("tools", "ztunnel")

// TableVersion is the schema version of the pre-generated table. A table written by a newer
// generator than this agent understands is refused rather than half-read, so a schema change
// degrades to the next fallback rung instead of to wrong offsets.
//
// v2 replaced a flat map of purpose-named offsets with per-type layouts keyed by the Rust type
// and field names, so an entry transcribes the debug info instead of a reading of it, and a
// later agent can use a field the generator never knew was interesting.
const TableVersion = 2

var (
	// TableBytes lets a distribution add its own pre-generated table on top of the built-in
	// one(spm-agent embeds the table its workflow maintains and injects it here). It does not
	// REPLACE the built-in table - the two are chained - so shipping a table that covers one
	// extra build cannot cost coverage of every build rover already knows.
	TableBytes []byte
	// TableFile, when set, adds a table read from disk ahead of both of the above, so a node
	// can be taught about a ztunnel build nobody has shipped an entry for - a vendor rebuild,
	// say - by mounting a file instead of waiting for a new agent image.
	TableFile = os.Getenv("ROVER_ZTUNNEL_OFFSET_TABLE")
)

// Build identifies one exact ztunnel binary an entry applies to.
//
// BuildID is the only field matching ever uses. Release and Platform are provenance: which
// ztunnel release the binary came from and for which target. They are recorded as separate
// fields rather than folded into a display string because the generator's "which versions are
// already covered" step reads Release - parsing a version back out of a free-text label would
// mean a mis-typed label silently disabled that check.
type Build struct {
	// BuildID is the hex GNU build ID: the primary key, and the only one that identifies a
	// binary exactly - see ReadELFBuildID.
	BuildID string `json:"buildId"`
	// Version and GitRevision are what this binary's own `ztunnel version` reports. They are the
	// FALLBACK key, used when a binary's build ID cannot be read at all(a stripped note section).
	// Both are recorded because ztunnel fills them from the same source today but has not always.
	//
	// They are recorded UNCONDITIONALLY - even for a build whose revision cannot be a match key
	// (see BuildStatus). Storing them is separate from matching on them: keeping the information
	// costs nothing and helps diagnosis, while whether a revision is USED as a key is decided at
	// load time from BuildStatus, not by dropping the data here.
	Version     string `json:"version,omitempty"`
	GitRevision string `json:"gitRevision,omitempty"`
	// BuildStatus is what `ztunnel version` reported as its build status("Clean" for an
	// unmodified checkout). It is what decides whether Version/GitRevision may serve as a
	// fallback match key: a non-clean build's revision names the commit it started from, not the
	// tree it was compiled from, so it is recorded but never indexed. An empty value(older table
	// entries) is treated as clean for backward compatibility.
	BuildStatus string `json:"buildStatus,omitempty"`
	// RustVersion is diagnostic provenance only - it never affects matching. Recorded so an
	// operator inspecting an entry can see the toolchain it was built with.
	RustVersion string `json:"rustVersion,omitempty"`
	// Release is the ZTUNNEL release this binary was published as - the tag of the istio/ztunnel
	// repository and its image, e.g. "1.28.3". It is a property of ztunnel, NOT the istio version
	// the running mesh reports(which is a separate, deployment-set value the agent never trusts;
	// see BuildInfo.IstioVersion). It is GENERATOR provenance only - it drives the "which ztunnel
	// releases are already covered" step - and is never matched at runtime.
	Release string `json:"release,omitempty"`
	// Platform is the target it was published for, e.g. "linux/amd64".
	Platform string `json:"platform,omitempty"`
}

// String renders a build for humans, e.g. `istio/ztunnel:1.28.3 linux/amd64 (33cf05af…)`.
func (b Build) String() string {
	switch {
	case b.Release != "" && b.Platform != "":
		return fmt.Sprintf("istio/ztunnel:%s %s (%s)", b.Release, b.Platform, b.BuildID)
	case b.Release != "":
		return fmt.Sprintf("istio/ztunnel:%s (%s)", b.Release, b.BuildID)
	default:
		return b.BuildID
	}
}

// Entry maps one or more exact ztunnel binaries to the layout they share. Several builds share
// one entry whenever they were compiled from the same type definitions with the same toolchain,
// which is the common case across the patch releases of one minor version - and, as measured,
// across whole minor versions when the probed structs did not change.
type Entry struct {
	Builds []Build `json:"builds"`
	// Layouts is the transcribed debug info: each Rust type with its size and every field offset.
	// Storing it per type, under the names ztunnel's own source uses, is what lets the probe grow
	// to read another field without regenerating entries that already shipped.
	Layouts Layouts `json:"layouts"`
}

// describe names an entry for an error message.
func (e *Entry) describe() string {
	parts := make([]string, 0, len(e.Builds))
	for _, build := range e.Builds {
		parts = append(parts, build.String())
	}
	return strings.Join(parts, ", ")
}

// Table is the parsed pre-generated table, indexed for lookup by build ID.
type Table struct {
	Version int      `json:"version"`
	Entries []*Entry `json:"entries"`

	byBuildID map[string]*Offsets
	// byRevision is the fallback index, keyed by the revisions `ztunnel version` reports. Only
	// clean builds are indexed - see BuildInfo.MatchKeys.
	byRevision map[string]*Offsets
}

// ParseTable decodes and fully validates a table. Validation happens at LOAD time
// rather than at use time so a malformed or corrupted table is reported once, loudly, at
// startup - instead of silently producing a miss on every connection later on.
func ParseTable(data []byte) (*Table, error) {
	table := &Table{}
	if err := json.Unmarshal(data, table); err != nil {
		return nil, fmt.Errorf("cannot parse the ztunnel offset table: %w", err)
	}
	if table.Version != TableVersion {
		return nil, fmt.Errorf("unsupported ztunnel offset table version %d, this agent understands %d",
			table.Version, TableVersion)
	}
	table.byBuildID = make(map[string]*Offsets)
	table.byRevision = make(map[string]*Offsets)
	for i, entry := range table.Entries {
		if len(entry.Layouts) == 0 {
			return nil, fmt.Errorf("entry %d has no layouts", i)
		}
		// Resolving here rather than per lookup means a table that cannot be composed into usable
		// offsets is rejected once, at load, instead of failing quietly on every connection.
		offsets, err := entry.Layouts.Resolve()
		if err != nil {
			return nil, fmt.Errorf("entry %d (%s) has unusable layouts: %w", i, entry.describe(), err)
		}
		if len(entry.Builds) == 0 {
			return nil, fmt.Errorf("entry %d matches no build", i)
		}
		for _, build := range entry.Builds {
			id := normalizeBuildID(build.BuildID)
			if id == "" {
				return nil, fmt.Errorf("entry %d has a build with no build id", i)
			}
			if _, dup := table.byBuildID[id]; dup {
				return nil, fmt.Errorf("build id %s appears in more than one entry", id)
			}
			resolved := *offsets
			table.byBuildID[id] = &resolved
			// index the revisions too, for the binaries whose build ID cannot be read. This is
			// where the store/match split is enforced: the entry may CARRY a revision for a
			// non-clean build, but MatchKeys - given the build's real BuildStatus - refuses to
			// hand it back as a key, so only revisions that actually identify a binary are
			// indexed. A revision shared by two entries is NOT an error the way a shared build ID
			// is(the fallback simply cannot disambiguate them), so the first one wins.
			info := &BuildInfo{
				Version:     build.Version,
				GitRevision: build.GitRevision,
				BuildStatus: build.BuildStatus,
			}
			for _, key := range info.MatchKeys() {
				key = normalizeBuildID(key)
				if _, taken := table.byRevision[key]; taken {
					// Two entries report the same revision; the fallback cannot tell them apart, so
					// the first one indexed wins. Worth a line because a revision lookup then quietly
					// answers from whichever entry happened to load first.
					log.Debugf("ztunnel revision %s is claimed by more than one entry; "+
						"the revision fallback will use the first and ignore the rest", key)
					continue
				}
				table.byRevision[key] = &resolved
			}
		}
	}
	return table, nil
}

// Lookup returns the offsets recorded for a build ID, or nil when the table does not know it.
func (t *Table) Lookup(buildID string) *Offsets {
	if t == nil {
		return nil
	}
	return t.byBuildID[normalizeBuildID(buildID)]
}

// LookupByRevision returns the offsets recorded for a revision `ztunnel version` reported.
//
// This is a FALLBACK for binaries whose build ID cannot be read, and is deliberately not tried
// when a build ID was read but simply missed: a build-ID miss means "this exact binary is not one
// that was measured", and answering it from another binary that merely shares a revision is
// precisely the mistake keying on build ID exists to prevent.
func (t *Table) LookupByRevision(info *BuildInfo) *Offsets {
	if t == nil {
		return nil
	}
	for _, key := range info.MatchKeys() {
		if offsets := t.byRevision[normalizeBuildID(key)]; offsets != nil {
			return offsets
		}
	}
	return nil
}

// normalizeBuildID makes matching insensitive to the hex case and surrounding whitespace a
// hand-maintained entry may pick up.
func normalizeBuildID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

// LoadTable resolves the active table by CHAINING every source, most specific first:
// the operator's mounted file, then whatever the distribution injected, then the table built
// into rover. The first source that knows a build ID answers for it.
//
// Chaining rather than replacing is what makes the narrow sources safe to use: mounting a file
// to teach one node about one vendor rebuild, or shipping a distribution table covering a
// handful of builds, must not cost the coverage of everything rover already knows. A
// configured-but-unreadable file is still a hard error - an operator sets that path precisely
// because the built-in answer is wrong for their ztunnel, so silently ignoring it would use the
// very offsets they were overriding.
func LoadTable() (*Table, error) {
	var sources []*Table

	if TableFile != "" {
		data, err := os.ReadFile(TableFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read the configured ztunnel offset table %s: %w",
				TableFile, err)
		}
		table, err := ParseTable(data)
		if err != nil {
			return nil, fmt.Errorf("the configured ztunnel offset table %s is unusable: %w", TableFile, err)
		}
		log.Debugf("loaded the operator-mounted ztunnel offset table %s, covering %d build(s)",
			TableFile, len(table.byBuildID))
		sources = append(sources, table)
	}

	if len(TableBytes) > 0 {
		table, err := ParseTable(TableBytes)
		if err != nil {
			return nil, fmt.Errorf("the injected ztunnel offset table is unusable: %w", err)
		}
		log.Debugf("loaded the injected(distribution) ztunnel offset table, covering %d build(s)",
			len(table.byBuildID))
		sources = append(sources, table)
	}

	builtin, err := BuiltinTable()
	if err != nil {
		return nil, err
	}
	log.Debugf("loaded the built-in ztunnel offset table, covering %d build(s)", len(builtin.byBuildID))
	sources = append(sources, builtin)

	combined := chainTables(sources...)
	log.Debugf("active ztunnel offset table composed from %d source(s), %d build(s) in total",
		len(sources), len(combined.byBuildID))
	return combined, nil
}

// chainTables folds several tables into one whose lookups try each in order. Entries are kept
// for reporting; the index resolves ties in favor of the earlier(more specific) source.
func chainTables(sources ...*Table) *Table {
	combined := &Table{Version: TableVersion, byBuildID: make(map[string]*Offsets)}
	for _, source := range sources {
		if source == nil {
			continue
		}
		combined.Entries = append(combined.Entries, source.Entries...)
		for buildID, offsets := range source.byBuildID {
			if _, taken := combined.byBuildID[buildID]; taken {
				// A higher-priority source already answered for this build id, so this one is
				// dropped. Sources are chained most-specific-first, so this is exactly an override
				// taking effect - logging it lets an operator confirm their mounted or injected
				// entry is the one being used instead of the built-in offsets.
				log.Debugf("ztunnel build id %s is served by a higher-priority table; "+
					"a lower-priority source's entry for it is shadowed", buildID)
				continue
			}
			combined.byBuildID[buildID] = offsets
		}
	}
	return combined
}
