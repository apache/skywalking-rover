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

package logger

import (
	"bytes"
	"strings"
	"testing"
)

// applyConfig runs the same setup path the module bootstrap uses and redirects
// both loggers to buffers so the emitted output can be asserted.
func applyConfig(t *testing.T, level, debugModules string) (base, debug *bytes.Buffer) {
	t.Helper()
	if err := setupLogger(&Config{Level: level, DebugModules: debugModules}); err != nil {
		t.Fatalf("setupLogger: %v", err)
	}
	base, debug = &bytes.Buffer{}, &bytes.Buffer{}
	root.SetOutput(base)
	debugRoot.SetOutput(debug)
	return base, debug
}

func emitted(base, debug *bytes.Buffer, marker string) bool {
	return strings.Contains(base.String(), marker) || strings.Contains(debug.String(), marker)
}

func TestDebugModulesElevatesOnlyAllowlisted(t *testing.T) {
	// only the ztunnel module is elevated; the connection module stays at INFO.
	base, debug := applyConfig(t, "info", "accesslog.collector.ztunnel")

	ztunnel := GetLogger("accesslog", "collector", "ztunnel")
	conn := GetLogger("access_log", "collector", "connection")

	ztunnel.Debugf(" zt-debug %d", 1)
	conn.Debugf("conn-debug %d", 2)

	if !emitted(base, debug, "zt-debug") {
		t.Errorf("expected the allowlisted ztunnel module debug log to be emitted")
	}
	if emitted(base, debug, "conn-debug") {
		t.Errorf("expected the non-allowlisted connection module debug log to be suppressed at info level")
	}
}

func TestDebugModulesPrefixMatchesChildrenNotSiblings(t *testing.T) {
	// a parent prefix elevates its child module, but not a same-prefixed sibling.
	base, debug := applyConfig(t, "info", "accesslog.collector")

	child := GetLogger("accesslog", "collector", "ztunnel")
	// "accesslog.collectorx" must NOT match the "accesslog.collector" prefix.
	sibling := GetLogger("accesslog", "collectorx")

	child.Debugf("child-debug")
	sibling.Debugf("sibling-debug")
	if !emitted(base, debug, "child-debug") {
		t.Errorf("expected the child module debug log to be emitted")
	}
	if emitted(base, debug, "sibling-debug") {
		t.Errorf("expected the sibling module debug log to be suppressed")
	}
}

func TestGlobalDebugLevelEmitsAllModules(t *testing.T) {
	// with no allowlist but a global debug level, every module logs at debug.
	base, debug := applyConfig(t, "debug", "")

	anyMod := GetLogger("access_log", "collector", "connection")
	anyMod.Debugf("global-debug")
	if !emitted(base, debug, "global-debug") {
		t.Errorf("expected debug logs when the global level is debug")
	}
}

func TestInfoStillEmittedForNonAllowlistedModule(t *testing.T) {
	// elevating one module must not suppress the info logs of the others.
	base, debug := applyConfig(t, "info", "accesslog.collector.ztunnel")

	conn := GetLogger("access_log", "collector", "connection")
	conn.Infof("conn-info")
	if !emitted(base, debug, "conn-info") {
		t.Errorf("expected info logs to be emitted for non-allowlisted modules")
	}
}

// TestElevatedModuleDoesNotDropInfoAboveGlobalLevel guards the severity-inversion
// bug: an elevated module must emit its OWN info/warn lines even when the global
// level is higher(here warn), not just its debug lines.
func TestElevatedModuleDoesNotDropInfoAboveGlobalLevel(t *testing.T) {
	base, debug := applyConfig(t, "warn", "accesslog.collector.ztunnel")

	zt := GetLogger("accesslog", "collector", "ztunnel")
	zt.Debugf("zt-elevated-debug")
	zt.Infof("zt-elevated-info")
	zt.Warnf("zt-elevated-warn")

	if !emitted(base, debug, "zt-elevated-debug") {
		t.Errorf("expected the elevated module to emit debug even when global level is warn")
	}
	if !emitted(base, debug, "zt-elevated-info") {
		t.Errorf("expected the elevated module to emit info even when global level is warn(severity inversion)")
	}
	if !emitted(base, debug, "zt-elevated-warn") {
		t.Errorf("expected the elevated module to emit warn")
	}

	// a non-elevated module still respects the global(warn) level: info dropped.
	other := GetLogger("access_log", "collector", "connection")
	other.Infof("other-info-dropped")
	if emitted(base, debug, "other-info-dropped") {
		t.Errorf("expected a non-elevated module info to be dropped at global warn level")
	}
}

// TestSetupReAppliesToLoggersCreatedBeforeConfig covers the registry re-apply
// loop, the sole mechanism that elevates package-level loggers created at import
// time(before setupLogger runs).
func TestSetupReAppliesToLoggersCreatedBeforeConfig(t *testing.T) {
	// create the logger BEFORE the config that should elevate it exists.
	pre := GetLogger("accesslog", "collector", "ztunnel")

	base, debug := applyConfig(t, "info", "accesslog.collector.ztunnel")
	pre.Debugf("pre-created-debug")
	if !emitted(base, debug, "pre-created-debug") {
		t.Errorf("expected setupLogger to re-apply the debug allowlist to a logger created before it ran")
	}
}
