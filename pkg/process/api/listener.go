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

package api

type ProcessListener interface {
	// AddNewProcess detect new process
	AddNewProcess(pid int32, entities []ProcessInterface)
	// RemoveProcess process been dead
	RemoveProcess(pid int32, entities []ProcessInterface)
	// RecheckAllProcesses recheck all process with interval, make sure all processes synchronize success
	RecheckAllProcesses(processes map[int32][]ProcessInterface)
}
