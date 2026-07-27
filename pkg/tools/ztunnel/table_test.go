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
	"testing"
)

func tableJSON(t *testing.T, entries ...*Entry) []byte {
	t.Helper()
	data, err := json.Marshal(&Table{Version: TableVersion, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseOffsetTableLookupByBuildID(t *testing.T) {
	const id = "90b4ef913a502003bf70f6f1265305a2131b03aa"
	table, err := ParseTable(tableJSON(t, &Entry{
		Builds:  []Build{{BuildID: id, Release: "1.29.0", Platform: "linux/amd64"}},
		Layouts: validLayouts(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := table.Lookup(id)
	if got == nil {
		t.Fatal("lookup by the exact build id found nothing")
	}
	if got.DestinationCluster != validOffsets().DestinationCluster {
		t.Fatalf("destinationCluster = %d; want %d", got.DestinationCluster, validOffsets().DestinationCluster)
	}
	// the source must be stamped so the stats can report which rung answered
	if got.Source != OffsetSourceTable {
		t.Fatalf("source = %q; want %q", got.Source, OffsetSourceTable)
	}
	// a build id the table does not cover must MISS, not fall back to some other entry:
	// using another binary's offsets is exactly the failure mode the build-id key prevents
	if other := table.Lookup("ffffffffffffffffffffffffffffffffffffffff"); other != nil {
		t.Fatalf("an unknown build id resolved to %+v", *other)
	}
}

func TestParseOffsetTableIsCaseAndSpaceInsensitive(t *testing.T) {
	table, err := ParseTable(tableJSON(t, &Entry{
		Builds:  []Build{{BuildID: "  90B4EF913A502003BF70F6F1265305A2131B03AA "}},
		Layouts: validLayouts(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if table.Lookup("90b4ef913a502003bf70f6f1265305a2131b03aa") == nil {
		t.Fatal("a build id differing only in case/whitespace failed to match")
	}
}

// One entry covering several build ids is the normal shape: the patch builds of a minor
// version share a layout, and generating one entry per patch would bloat the table.
func TestParseOffsetTableEntryCoversMultipleBuilds(t *testing.T) {
	ids := []string{
		"90b4ef913a502003bf70f6f1265305a2131b03aa",
		"c66f2da111e6752019d5cc18dafd39a58510ef00",
	}
	builds := []Build{{BuildID: ids[0], Release: "1.29.0"}, {BuildID: ids[1], Release: "1.26.0"}}
	table, err := ParseTable(tableJSON(t, &Entry{Builds: builds, Layouts: validLayouts()}))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if table.Lookup(id) == nil {
			t.Fatalf("build id %s in a multi-id entry failed to match", id)
		}
	}
}

// A table that would hand out wrong or ambiguous offsets must be refused WHOLE at load time.
// Accepting it and failing later would mean reading ztunnel memory at made-up offsets.
func TestParseOffsetTableRejectsUnusable(t *testing.T) {
	badLayouts := validLayouts()
	badLayouts[TypeCommonTrafficLabels].Fields["destination_cluster"] = 10_000

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"not json", []byte("this is not a table")},
		{
			"unsupported schema version",
			[]byte(fmt.Sprintf(`{"version":%d,"entries":[]}`, TableVersion+1)),
		},
		{"entry without layouts", tableJSON(t, &Entry{Builds: []Build{{BuildID: "aa"}}})},
		{"entry without builds", tableJSON(t, &Entry{Layouts: validLayouts()})},
		{"entry with invalid layouts", tableJSON(t, &Entry{Builds: []Build{{BuildID: "aa"}}, Layouts: badLayouts})},
		{
			"same build id in two entries",
			tableJSON(t,
				&Entry{Builds: []Build{{BuildID: "aa"}}, Layouts: validLayouts()},
				&Entry{Builds: []Build{{BuildID: "AA"}}, Layouts: validLayouts()}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseTable(tc.data); err == nil {
				t.Fatalf("ParseTable accepted an unusable table (%s)", tc.name)
			}
		})
	}
}

// A nil table must answer "I don't know" rather than panic, since that is the state on any
// deployment that ships no table at all.
func TestNilOffsetTableLookup(t *testing.T) {
	var table *Table
	if table.Lookup("anything") != nil {
		t.Fatal("a nil table returned offsets")
	}
}

// The three sources must CHAIN, not replace one another. Mounting a file to teach one node about
// one vendor rebuild, or shipping a distribution table covering a handful of builds, must not
// cost the coverage of everything already built in - that would turn a narrow addition into a
// broad regression.
func TestLoadTableChainsSourcesMostSpecificFirst(t *testing.T) {
	builtinOnly := validLayouts()
	injectedOnly := validLayouts()
	injectedOnly[TypeCommonTrafficLabels].Fields["destination_cluster"] = 208
	shared := validLayouts()
	shared[TypeCommonTrafficLabels].Fields["destination_cluster"] = 200

	const (
		builtinID  = "aa11111111111111111111111111111111111111"
		injectedID = "bb22222222222222222222222222222222222222"
		sharedID   = "cc33333333333333333333333333333333333333"
	)

	builtin, err := ParseTable(tableJSON(t,
		&Entry{Builds: []Build{{BuildID: builtinID}}, Layouts: builtinOnly},
		&Entry{Builds: []Build{{BuildID: sharedID}}, Layouts: builtinOnly}))
	if err != nil {
		t.Fatal(err)
	}
	injected, err := ParseTable(tableJSON(t,
		&Entry{Builds: []Build{{BuildID: injectedID}}, Layouts: injectedOnly},
		&Entry{Builds: []Build{{BuildID: sharedID}}, Layouts: shared}))
	if err != nil {
		t.Fatal(err)
	}

	chained := chainTables(injected, builtin)

	// a build only the built-in table knows must still resolve
	if got := chained.Lookup(builtinID); got == nil {
		t.Fatal("a build id known only to the built-in table was lost when a narrower table was added")
	}
	if got := chained.Lookup(injectedID); got == nil {
		t.Fatal("a build id known only to the injected table did not resolve")
	}
	// where both know a build, the more specific source wins
	got := chained.Lookup(sharedID)
	if got == nil {
		t.Fatal("a build id known to both tables did not resolve")
	}
	if got.DestinationCluster != 200 {
		t.Fatalf("destinationCluster = %d; want 200, the more specific source must win",
			got.DestinationCluster)
	}
}

// The table compiled into rover must always parse: it ships with the binary, so a broken one is
// a build mistake that would otherwise look like "no ztunnel is covered" at runtime.
func TestBuiltinTableParses(t *testing.T) {
	table, err := BuiltinTable()
	if err != nil {
		t.Fatalf("the built-in offset table is unusable: %v", err)
	}
	if table == nil {
		t.Fatal("BuiltinTable returned no table")
	}
	for _, entry := range table.Entries {
		if _, err := entry.Layouts.Resolve(); err != nil {
			t.Errorf("built-in entry %s has unusable layouts: %v", entry.describe(), err)
		}
		if len(entry.Builds) == 0 {
			t.Errorf("built-in entry matches no build")
		}
		for _, build := range entry.Builds {
			// the release is what the generator's skip-already-covered step reads, so an entry
			// without it would silently make that version get rebuilt on every run
			if build.Release == "" {
				t.Errorf("built-in build %s records no release", build.BuildID)
			}
		}
	}
}
