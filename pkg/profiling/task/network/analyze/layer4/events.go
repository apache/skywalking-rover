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

package layer4

import (
	"encoding/json"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"

	"github.com/sirupsen/logrus"
)

var log = logger.GetLogger("profiling", "task", "network", "layer4")

// SocketExceptionOperationEvent Socket have been retransmitted/drop the package event
type SocketExceptionOperationEvent struct {
	Pid            uint32
	SocketFamily   uint32
	RemoteAddrV4   uint32
	RemoteAddrV6   [16]uint8
	RemoteAddrPort uint32
	Type           base.SocketExceptionOperationType
}

func (l *Listener) handleSocketExceptionOperationEvent(data interface{}) {
	event := data.(*SocketExceptionOperationEvent)
	l.socketExceptionOperationLock.Lock()
	defer l.socketExceptionOperationLock.Unlock()

	key := SocketBasicKey{
		Pid:          event.Pid,
		Family:       event.SocketFamily,
		RemoteAddrV4: event.RemoteAddrV4,
		RemoteAddrV6: event.RemoteAddrV6,
		RemotePort:   event.RemoteAddrPort,
	}
	exceptionValue := l.socketExceptionStatics[key]
	if exceptionValue == nil {
		exceptionValue = &SocketExceptionValue{}
		l.socketExceptionStatics[key] = exceptionValue
	}

	switch event.Type {
	case base.SocketExceptionOperationRetransmit:
		exceptionValue.RetransmitCount++
	case base.SocketExceptionOperationDrop:
		exceptionValue.DropCount++
	default:
		log.Warnf("unknown socket exception operation type: %d", event.Type)
	}

	if log.Enable(logrus.DebugLevel) {
		marshal, _ := json.Marshal(event)
		log.Debugf("found socket exception operation event: %s", string(marshal))
	}
}

type SocketBasicKey struct {
	Pid          uint32
	Family       uint32
	RemoteAddrV4 uint32
	RemoteAddrV6 [16]uint8
	RemotePort   uint32
	LocalAddrV4  uint32
	LocalAddrV6  [16]uint8
	LocalPort    uint32
}

type SocketExceptionValue struct {
	DropCount       int
	RetransmitCount int
}
