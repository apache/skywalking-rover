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
	_ "embed"
	"fmt"
	"sync"
)

// builtinTableBytes is the offset table shipped inside rover, covering the UPSTREAM istio
// ztunnel releases.
//
// It exists because the layout cannot be learned from the binary the agent actually runs
// against: every official ztunnel image is built with `cargo build --release`, whose profile
// leaves `debug` off, so the released binaries carry a symbol table but no .debug_* sections.
// The offsets here were mined from separate debug builds of the SAME release tags and are keyed
// by the GNU build ID of the corresponding official image, so an entry only ever applies to the
// exact binary it was measured from.
//
// Distributions add their own builds on top through TableBytes, and an operator can add one more
// through TableFile; all three are chained by LoadTable, so this table is the floor rather than
// the whole answer.
//
//go:embed offsets_table.json
var builtinTableBytes []byte

var (
	builtinTableOnce sync.Once
	builtinTable     *Table
	builtinTableErr  error
)

// BuiltinTable parses the table compiled into rover. The result is cached: it is the same bytes
// on every call, and parsing validates every entry.
//
// A parse failure here is a build-time mistake(the bytes ship with the binary), so it is
// surfaced as an error rather than quietly skipped - a silently dropped built-in table would
// look exactly like "this ztunnel is not covered" and send every node down the calibration path.
func BuiltinTable() (*Table, error) {
	builtinTableOnce.Do(func() {
		builtinTable, builtinTableErr = ParseTable(builtinTableBytes)
		if builtinTableErr != nil {
			builtinTableErr = fmt.Errorf("the ztunnel offset table built into rover is unusable: %w",
				builtinTableErr)
		}
	})
	return builtinTable, builtinTableErr
}
