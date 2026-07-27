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

import "testing"

// Every line below was captured from a real `ztunnel version` run - two upstream images and the
// vendor build running in production - so the parser is pinned against output that actually
// occurs, including the ways these builds disagree with each other.
const (
	// upstream istio/ztunnel:1.26.0 - note it reports NO istio version of its own
	upstreamOldOutput = `version.BuildInfo{Version:"2f601957bd172b34990612f4d8f847cadf4e880d", ` +
		`GitRevision:"2f601957bd172b34990612f4d8f847cadf4e880d", RustVersion:"1.85.1", ` +
		`BuildProfile:"release", BuildStatus:"Clean", GitTag:"1.26.0-beta.0-1-g2f60195", IstioVersion:"unknown"}`
	// upstream istio/ztunnel:1.28.3 - this one does carry an istio version
	upstreamNewOutput = `version.BuildInfo{Version:"8bda303b0cfac76d3ab99b7e1ed3def71082fc9f", ` +
		`GitRevision:"8bda303b0cfac76d3ab99b7e1ed3def71082fc9f", RustVersion:"1.90.0", ` +
		`BuildProfile:"release", BuildStatus:"Clean", IstioVersion:"1.28.3", CryptoProvider:"tls-aws-lc"}`
	// the vendor rebuild in production: a MODIFIED tree, so its revision names a commit it is not
	vendorDirtyOutput = `version.BuildInfo{Version:"77374b17862c941a7cc1ee6d7b1fb80c6a3b9800-dirty", ` +
		`GitRevision:"77374b17862c941a7cc1ee6d7b1fb80c6a3b9800-dirty", RustVersion:"1.90.0", ` +
		`BuildProfile:"release", BuildStatus:"Modified", IstioVersion:"unknown", CryptoProvider:"tls-aws-lc"}`
)

func TestParseBuildInfo(t *testing.T) {
	info, err := ParseBuildInfo(upstreamNewOutput)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ field, got, want string }{
		{"Version", info.Version, "8bda303b0cfac76d3ab99b7e1ed3def71082fc9f"},
		{"GitRevision", info.GitRevision, "8bda303b0cfac76d3ab99b7e1ed3def71082fc9f"},
		{"BuildStatus", info.BuildStatus, "Clean"},
		{"IstioVersion", info.IstioVersion, "1.28.3"},
		{"RustVersion", info.RustVersion, "1.90.0"},
	} {
		if check.got != check.want {
			t.Errorf("%s = %q; want %q", check.field, check.got, check.want)
		}
	}
}

// The version subcommand prints the struct on its own line, possibly after other output; the
// parser must find it rather than assume it is the whole input.
func TestParseBuildInfoFindsTheLine(t *testing.T) {
	if _, err := ParseBuildInfo("some warning\n" + upstreamOldOutput + "\n"); err != nil {
		t.Fatalf("failed to find the BuildInfo line among other output: %v", err)
	}
	if _, err := ParseBuildInfo("no build info here"); err == nil {
		t.Fatal("expected an error when the output carries no BuildInfo line")
	}
}

// A clean build may be matched by its revision. This is the whole point of the fallback key.
func TestBuildInfoMatchKeysAcceptsCleanBuilds(t *testing.T) {
	for name, output := range map[string]string{
		"upstream 1.26.0": upstreamOldOutput,
		"upstream 1.28.3": upstreamNewOutput,
	} {
		info, err := ParseBuildInfo(output)
		if err != nil {
			t.Fatal(err)
		}
		keys := info.MatchKeys()
		if len(keys) == 0 {
			t.Fatalf("%s: a clean build produced no match keys", name)
		}
		for _, key := range keys {
			if key == "" || key == "unknown" {
				t.Errorf("%s: unusable match key %q", name, key)
			}
		}
	}
}

// A MODIFIED build must never be matchable by revision: its revision is the commit it started
// from, so any number of different binaries report the same string. This is the case that occurs
// in production, and matching it against an upstream entry would read a differently-laid-out
// struct at the wrong offsets.
func TestBuildInfoMatchKeysRefusesModifiedBuilds(t *testing.T) {
	info, err := ParseBuildInfo(vendorDirtyOutput)
	if err != nil {
		t.Fatal(err)
	}
	if keys := info.MatchKeys(); len(keys) != 0 {
		t.Fatalf("a Modified build offered match keys %v; it must offer none", keys)
	}
	// even with the status stripped, the -dirty suffix alone must disqualify it
	info.BuildStatus = ""
	if keys := info.MatchKeys(); len(keys) != 0 {
		t.Fatalf("a -dirty revision offered match keys %v; it must offer none", keys)
	}
}

// The istio version must never become a match key: measured across real images it is
// inconsistent(upstream 1.26.0 reports "unknown") and comes from a deployment-set env var.
func TestBuildInfoNeverMatchesOnIstioVersion(t *testing.T) {
	info, err := ParseBuildInfo(upstreamNewOutput)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range info.MatchKeys() {
		if key == info.IstioVersion {
			t.Fatalf("the istio version %q was offered as a match key", key)
		}
	}
}

// End to end: a table entry generated from a clean upstream build must be findable by the
// revision that build reports, and a table must never answer for a modified build.
func TestTableLookupByRevision(t *testing.T) {
	clean, err := ParseBuildInfo(upstreamNewOutput)
	if err != nil {
		t.Fatal(err)
	}
	table, err := ParseTable(tableJSON(t, &Entry{
		Builds: []Build{{
			BuildID:     "33cf05af190fae07d66bd8f7fd239bd464da92c2",
			Version:     clean.Version,
			GitRevision: clean.GitRevision,
			Release:     "1.28.3",
		}},
		Layouts: validLayouts(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := table.LookupByRevision(clean); got == nil {
		t.Fatal("a clean build's revision did not resolve against the entry generated from it")
	}

	dirty, err := ParseBuildInfo(vendorDirtyOutput)
	if err != nil {
		t.Fatal(err)
	}
	if got := table.LookupByRevision(dirty); got != nil {
		t.Fatalf("a modified build resolved to %+v; it must never match by revision", *got)
	}
}

// The generator records a build's revision unconditionally - including a non-clean build's. The
// store/match split means that revision must be KEPT in the entry(for provenance and diagnosis)
// yet must NOT be reachable by a revision lookup. This pins both halves at once.
func TestTableStoresDirtyRevisionButNeverMatchesIt(t *testing.T) {
	dirty, err := ParseBuildInfo(vendorDirtyOutput)
	if err != nil {
		t.Fatal(err)
	}
	entry := &Entry{
		Builds: []Build{{
			BuildID:     "12f0f401244caa6c03f1c2604527dbc117b1af61",
			Version:     dirty.Version,
			GitRevision: dirty.GitRevision,
			BuildStatus: dirty.BuildStatus, // "Modified"
			Release:     "1.28.3-vendor",
		}},
		Layouts: validLayouts(),
	}
	table, err := ParseTable(tableJSON(t, entry))
	if err != nil {
		t.Fatal(err)
	}

	// stored: the parsed entry still carries the dirty revision, it was not dropped
	stored := table.Entries[0].Builds[0]
	if stored.Version != dirty.Version || stored.GitRevision != dirty.GitRevision {
		t.Fatalf("the dirty revision was dropped from the entry: got version=%q gitRevision=%q",
			stored.Version, stored.GitRevision)
	}
	if stored.BuildStatus != "Modified" {
		t.Fatalf("build status = %q; want the stored Modified", stored.BuildStatus)
	}

	// not matchable: it is still reachable by its exact build ID, but never by its revision
	if got := table.Lookup(stored.BuildID); got == nil {
		t.Fatal("the dirty build must still be reachable by its exact build id")
	}
	if got := table.LookupByRevision(dirty); got != nil {
		t.Fatalf("the stored dirty revision was indexed and matched %+v; it must never be", *got)
	}
}
