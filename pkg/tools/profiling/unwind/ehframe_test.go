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

package unwind

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

var amd64RegisterNames = map[string]int{
	"rax": 0, "rdx": 1, "rcx": 2, "rbx": 3, "rsi": 4, "rdi": 5, "rbp": 6, "rsp": 7,
	"r8": 8, "r9": 9, "r10": 10, "r11": 11, "r12": 12, "r13": 13, "r14": 14, "r15": 15, "ra": 16,
}

// TestParseEHFrameWithReadelf compares the rows with the "readelf --debug-dump=frames-interp" output
func TestParseEHFrameWithReadelf(t *testing.T) {
	if runtime.GOARCH != ArchAMD64.Name {
		t.Skip("only verify on amd64")
	}
	if _, err := exec.LookPath("readelf"); err != nil {
		t.Skip("readelf not found")
	}
	files := []string{
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
		"/usr/lib/x86_64-linux-gnu/libm.so.6",
		"/usr/bin/bash",
	}
	tested := 0
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		tested++
		t.Run(f, func(t *testing.T) {
			verifyWithReadelf(t, f)
		})
	}
	if tested == 0 {
		t.Skip("no ELF file found for verify")
	}
}

func verifyWithReadelf(t *testing.T, path string) {
	table, err := LoadFrameTable(ArchAMD64, path)
	if err != nil {
		t.Fatalf("load frame table failure: %v", err)
	}
	// readelf exits with non-zero when the separate debug file is missing, the output still usable
	output, _ := exec.Command("readelf", "--wide", "--debug-dump=frames-interp", path).Output()

	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var columns []string
	inFDE := false
	rows, mismatches := 0, 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.Contains(line, " FDE "):
			inFDE = true
			columns = nil
		case strings.Contains(line, " CIE") || line == "":
			if line != "" {
				inFDE = false
			}
		case strings.HasPrefix(line, "LOC"):
			columns = strings.Fields(line)
		case inFDE && columns != nil:
			fields := strings.Fields(line)
			if len(fields) != len(columns) {
				continue
			}
			rows++
			if err := compareRow(table, columns, fields); err != nil {
				mismatches++
				if mismatches <= 10 {
					t.Errorf("%v", err)
				}
			}
		}
	}
	if rows == 0 {
		t.Fatalf("no rows verified")
	}
	t.Logf("verified %d rows of %d FDEs, mismatches: %d", rows, len(table.fdes), mismatches)
}

func compareRow(table *FrameTable, columns, fields []string) error {
	loc, err := strconv.ParseUint(fields[0], 16, 64)
	if err != nil {
		return err
	}
	row := table.FindRow(loc)
	if row == nil {
		return fmt.Errorf("0x%x: row not found", loc)
	}
	if cfa := formatCFA(row.CFA); cfa != fields[1] {
		return fmt.Errorf("0x%x: CFA expected %s, actual %s", loc, fields[1], cfa)
	}
	for i := 2; i < len(columns); i++ {
		reg, ok := amd64RegisterNames[columns[i]]
		if !ok {
			continue
		}
		if rule := formatRule(row.Regs[reg]); rule != fields[i] {
			return fmt.Errorf("0x%x: register %s expected %s, actual %s", loc, columns[i], fields[i], rule)
		}
	}
	return nil
}

func formatCFA(c CFARule) string {
	if c.Expr != nil {
		return "exp"
	}
	for name, reg := range amd64RegisterNames {
		if reg == c.Reg {
			return fmt.Sprintf("%s%+d", name, c.Offset)
		}
	}
	return fmt.Sprintf("r%d%+d", c.Reg, c.Offset)
}

func formatRule(r RegisterRule) string {
	switch r.Type {
	case RuleUnspecified, RuleUndefined:
		return "u"
	case RuleSameValue:
		return "s"
	case RuleOffset:
		return fmt.Sprintf("c%+d", r.Offset)
	case RuleValOffset:
		return fmt.Sprintf("v%+d", r.Offset)
	case RuleExpression:
		return "exp"
	case RuleValExpression:
		return "vexp"
	case RuleRegister:
		for name, reg := range amd64RegisterNames {
			if reg == r.Reg {
				return name
			}
		}
	}
	return "?"
}
