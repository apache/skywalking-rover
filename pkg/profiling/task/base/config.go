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

package base

type TaskConfig struct {
	OnCPU   *OnCPUConfig   `mapstructure:"on_cpu"`  // ON_CPU type of profiling task config
	Network *NetworkConfig `mapstructure:"network"` // NETWORK type of profiling task config
}

type OnCPUConfig struct {
	Period string `mapstructure:"dump_period"` // The duration of dump stack
}

type NetworkConfig struct {
	ReportInterval  string                `mapstructure:"report_interval"`  // The duration of data report interval
	MeterPrefix     string                `mapstructure:"meter_prefix"`     // The prefix of meter name
	ProtocolAnalyze ProtocolAnalyzeConfig `mapstructure:"protocol_analyze"` // The 7-Layer protocol analyze
}

type ProtocolAnalyzeConfig struct {
	PerCPUBufferSize string         `mapstructure:"per_cpu_buffer"`
	Parallels        int            `mapstructure:"parallels"`
	QueueSize        int            `mapstructure:"queue_size"`
	Sampling         SamplingConfig `mapstructure:"sampling"`
}

type SamplingConfig struct {
	HTTP HTTPSamplingConfig `mapstructure:"http"`
}

type HTTPSamplingConfig struct {
	DefaultRequestEncoding  string `mapstructure:"default_request_encoding"`  // default http request body encoding
	DefaultResponseEncoding string `mapstructure:"default_response_encoding"` // default http response body encoding
}
