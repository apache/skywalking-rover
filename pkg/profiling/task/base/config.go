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

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/net/html/charset"
)

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

func (c *TaskConfig) Validate() error {
	var err error
	network := c.Network
	if network != nil {
		err = c.durationValidate(err, network.ReportInterval, "parsing report interval failure: %v")
		err = c.stringNotEmpty(err, network.MeterPrefix, "meter prefix must be set")

		protocolAnalyze := network.ProtocolAnalyze
		err = c.biggerThan(err, protocolAnalyze.Parallels, 0, "network protocol analyzer parallels must be bigger than 0")
		err = c.biggerThan(err, protocolAnalyze.QueueSize, 0, "network protocol analyzer queue size must be bigger than 0")

		httpSampling := protocolAnalyze.Sampling.HTTP
		err = c.validateHTTPEncoding(err, httpSampling.DefaultRequestEncoding, "request")
		err = c.validateHTTPEncoding(err, httpSampling.DefaultResponseEncoding, "response")
	}
	return err
}

func (c *TaskConfig) durationValidate(err error, value, message string) error {
	if err != nil {
		return err
	}
	_, err = time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf(message, err)
	}
	return nil
}

func (c *TaskConfig) stringNotEmpty(err error, value, message string) error {
	if err != nil {
		return err
	}
	if value == "" {
		return errors.New(message)
	}
	return nil
}

func (c *TaskConfig) biggerThan(err error, value, needs int, message string) error {
	if err != nil {
		return err
	}
	if value <= needs {
		return errors.New(message)
	}
	return nil
}

func (c *TaskConfig) validateHTTPEncoding(err error, encoding, configType string) error {
	if err != nil {
		return err
	}
	if encoding == "" {
		return fmt.Errorf("the default HTTP %s encoding must be set", configType)
	}
	if e, _ := charset.Lookup(encoding); e == nil {
		return fmt.Errorf("unknown charset: %s", encoding)
	}
	return nil
}
