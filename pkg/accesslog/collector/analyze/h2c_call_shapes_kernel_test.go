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

package analyze

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

// h2cShape classifies one socket call as BPF uploaded it (production switches: drop and skip on)
func h2cShape(e *events.SocketDataUploadEvent) string {
	switch {
	case e.PayloadSkipped0 == 1:
		return "skipped (payload only)"
	case e.HaveReduce == 1 && e.TotalSize0 > uint64(e.DataLen):
		return "tail-cut"
	case e.TotalSize0 <= 16 && uint64(e.DataLen) == e.TotalSize0 && e.DataLen >= 9:
		data := e.BufferData()
		if len(data) >= 9 && data[3] == 0 && e.TotalSize0 == 9 {
			return "standalone 9B DATA header"
		}
		return fmt.Sprintf("small full (type %d)", data[3])
	default:
		return "other full upload"
	}
}

// TestH2CCallShapes measures, for real Go net/http2 on both sides, what share of the uploaded calls are
// standalone 9-byte DATA headers (not batchable) versus tail-cut or skipped calls (batchable), per side and
// direction, with the production switches. It also logs the total size distribution of the calls whose
// uploaded data is 0-16 bytes, which is what the cluster histogram (by uploaded length) lumps together.
func TestH2CCallShapes(t *testing.T) {
	withH2CSkipDataPayload(t)
	requireBPF(t)
	common.SetMergeKernelLogs(true)
	defer common.SetMergeKernelLogs(false)
	for _, w := range []struct {
		name    string
		traffic func(run *h2cKernelRun)
	}{
		{"sequential 256KB", func(run *h2cKernelRun) { goH2CBodyTraffic(t, run, 16, 256*1024, 256*1024) }},
		{"many streams 256KB", func(run *h2cKernelRun) { goH2CManyStreams(t, run, 96, 8, 256*1024) }},
		{"many streams 64KB x32", func(run *h2cKernelRun) { goH2CManyStreams(t, run, 120, 32, 64*1024) }},
	} {
		run, _ := withAccessLogBatch(t, true, false, w.traffic)
		for _, conn := range run.conns {
			for _, d := range []enums.SocketDataDirection{enums.SocketDataDirectionIngress, enums.SocketDataDirectionEgress} {
				counts := map[string]int{}
				small := map[string]int{} // uploaded 0-16B, by total size bucket
				total := 0
				var last uint64
				for _, e := range conn.events[d] {
					if total > 0 && e.DataID0 == last {
						continue // a further chunk of the same call
					}
					last = e.DataID0
					total++
					counts[h2cShape(e)]++
					if e.DataLen <= 16 {
						switch {
						case e.TotalSize0 <= 16:
							small["total<=16"]++
						case e.TotalSize0 <= 4096:
							small["17-4096"]++
						case e.TotalSize0 <= 16393:
							small["4097-16393"]++
						default:
							small[">16393"]++
						}
					}
				}
				if total == 0 {
					continue
				}
				var parts []string
				for k, v := range counts {
					parts = append(parts, fmt.Sprintf("%s=%d (%.0f%%)", k, v, 100*float64(v)/float64(total)))
				}
				sort.Strings(parts)
				var sp []string
				for k, v := range small {
					sp = append(sp, fmt.Sprintf("%s=%d", k, v))
				}
				sort.Strings(sp)
				t.Logf("%s %s %s: %d calls: %s | uploaded<=16B by total size: %s", w.name, conn.name, directionName(d),
					total, strings.Join(parts, ", "), strings.Join(sp, ", "))
			}
		}
	}
}
