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

package events

import "sync"

// The socket data events are recycled only where their whole life is known: an event of a socket call that
// belongs to no protocol (or that the memory protection shed) goes from the reader straight to the flush
// queue, which owns it from then on (forwarder.SendTransferNoProtocolEventOwned), and the flush gives it back
// once its kernel log is in the batch. Every other event lives on in the buffers, the positions and the
// slices of the protocol analysis, which have no point where the last reference is known to be gone, and
// is left to the garbage collector.
var uploadEventPool = sync.Pool{New: func() any { return new(SocketDataUploadEvent) }}

// AcquireUploadEvent returns an empty event, what &SocketDataUploadEvent{} returns
func AcquireUploadEvent() *SocketDataUploadEvent {
	return uploadEventPool.Get().(*SocketDataUploadEvent)
}

// RecycleUploadEvent gives back an event nothing refers to anymore. Its buffer must have been released: it
// is dropped with the rest of the event.
func RecycleUploadEvent(e *SocketDataUploadEvent) {
	*e = SocketDataUploadEvent{}
	uploadEventPool.Put(e)
}
