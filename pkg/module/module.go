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

package module

import "context"

// Module define
type Module interface {
	// Name of module.
	// It would be use when declaring this module into configuration or other module need to reference.
	Name() string

	// RequiredModules means which modules do this module is depended on,
	// The current module started after the dependent modules are Start success.
	RequiredModules() []string

	// Config of this module
	// The config is automatically read from the configuration file before module Start
	Config() ConfigInterface

	// Start module
	// The module needs to return the start result after startup is completed
	Start(ctx context.Context, mgr *Manager) error

	// NotifyStartSuccess when all module have been start success
	NotifyStartSuccess()

	// Shutdown module, the sequence of shutdown is the reverse of the module Start
	// The shutdown would trigger in the following cases
	// 1. If other modules fail to start
	// 2. The module is actively shutdown through Manager.ShutdownModules
	// 3. The Rover receive the close SIGNAL
	Shutdown(ctx context.Context, mgr *Manager) error
}
