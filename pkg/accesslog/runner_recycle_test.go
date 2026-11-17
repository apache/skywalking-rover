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

package accesslog

import (
	"reflect"
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"

	"github.com/apache/skywalking-rover/pkg/accesslog/events"
)

// TestRecycleKernelLogEvent: only the event of an owned kernel log is recycled, and it is cleared
func TestRecycleKernelLogEvent(t *testing.T) {
	owned := &events.SocketDataUploadEvent{ConnectionID: 1, DataID0: 2, FunctionName: 3}
	recycleKernelLogEvent(common.NewOwnedKernelLogEvent(common.LogTypeKernelTransfer, owned))
	if !reflect.DeepEqual(*owned, events.SocketDataUploadEvent{}) {
		t.Fatalf("an owned event is not cleared when recycled: %+v", owned)
	}
	shared := &events.SocketDataUploadEvent{ConnectionID: 1, DataID0: 2, FunctionName: 3}
	recycleKernelLogEvent(common.NewKernelLogEvent(common.LogTypeKernelTransfer, shared))
	if shared.ConnectionID != 1 || shared.DataID0 != 2 {
		t.Fatalf("an event that is not owned is recycled")
	}
	if e := events.AcquireUploadEvent(); !reflect.DeepEqual(*e, events.SocketDataUploadEvent{}) {
		t.Fatalf("an acquired event is not empty: %+v", e)
	}
}
