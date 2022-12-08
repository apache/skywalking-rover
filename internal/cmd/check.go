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

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/apache/skywalking-rover/pkg/tools/operator"

	"github.com/cilium/ebpf/rlimit"

	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task"
	"github.com/apache/skywalking-rover/pkg/profiling/task/base"

	"github.com/spf13/cobra"

	"github.com/apache/skywalking-rover/pkg/boot"
)

func newCheckCmd() *cobra.Command {
	configPath := ""
	outputPath := ""
	outputFormat := ""
	cmd := &cobra.Command{
		Use: "check",
		RunE: func(cmd *cobra.Command, args []string) error {
			return check(configPath, outputPath, outputFormat)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "configs/rover_configs.yaml", "the rover config file path")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "output.txt", "the rover check output file")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "plain", "the check output format, support \"json\", \"plain\"")
	return cmd
}

func check(configPath, outputPath, format string) error {
	if configPath == "" || outputPath == "" {
		return fmt.Errorf("the config and output path is required")
	}

	err := os.MkdirAll(filepath.Dir(outputPath), os.ModePerm)
	if err != nil {
		log.Fatalf("failed to create the output file directory: %v", err)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		log.Fatalf("failed to create the output file: %v", err)
	}
	defer outFile.Close()

	notify := make(chan bool, 1)
	go func(notify chan bool) {
		err = boot.RunModules(context.Background(), configPath, func(manager *module.Manager) {
			// startup success
			processModuleStartSuccess(notify, nil, manager, outFile, format)
		})
		if err != nil {
			// startup failure
			processModuleStartSuccess(notify, err, nil, outFile, format)
		}
	}(notify)

	<-notify
	return nil
}

func processModuleStartSuccess(notify chan bool, err error, mgr *module.Manager, file io.Writer, format string) {
	data := &outputData{}
	defer func() {
		writeOutput(data, file, format)
		notify <- true
	}()
	if err != nil {
		data.Startup = err
		return
	}
	uname, err := operator.GetOSUname()
	if err != nil {
		data.Startup = err
		return
	}
	data.Kernel = uname.Release

	if err := rlimit.RemoveMemlock(); err != nil {
		data.Startup = err
		return
	}

	// wait processes
	processModule := mgr.FindModule(process.ModuleName).(*process.Module)
	var processes []api.ProcessInterface
	for i := 0; i < 3; i++ {
		processes = processModule.GetAllProcesses()
		if len(processes) != 0 {
			break
		}
		time.Sleep(time.Second)
	}
	if len(processes) == 0 {
		data.Startup = fmt.Errorf("no process")
		return
	}

	ctx := context.Background()
	data.OnCPU = testOnCPUProfiling(ctx, mgr, processes[0])
	data.OffCPU = testOffCPUProfiling(ctx, mgr, processes[0])
	data.Network = testNetworkProfiling(ctx, mgr, processes[0])
}

func testOnCPUProfiling(ctx context.Context, mgr *module.Manager, p api.ProcessInterface) error {
	return testWithRunner(ctx, base.TargetTypeOnCPU, &base.TaskConfig{
		OnCPU: &base.OnCPUConfig{
			Period: "9ms",
		},
	}, mgr, p)
}

func testOffCPUProfiling(ctx context.Context, mgr *module.Manager, p api.ProcessInterface) error {
	return testWithRunner(ctx, base.TargetTypeOffCPU, &base.TaskConfig{}, mgr, p)
}

func testNetworkProfiling(ctx context.Context, mgr *module.Manager, p api.ProcessInterface) error {
	return testWithRunner(ctx, base.TargetTypeNetworkTopology, &base.TaskConfig{
		Network: &base.NetworkConfig{
			MeterPrefix:    "test",
			ReportInterval: "10ms",
			ProtocolAnalyze: base.ProtocolAnalyzeConfig{
				PerCPUBufferSize: "10K",
				Parallels:        1,
				QueueSize:        5000,
			},
		},
	}, mgr, p)
}

func testWithRunner(ctx context.Context, taskType base.TargetType, taskConfig *base.TaskConfig,
	moduleManager *module.Manager, p api.ProcessInterface) error {
	runner, err := task.NewProfilingRunner(taskType, taskConfig, moduleManager)
	if err != nil {
		return err
	}

	if err := runner.Init(&base.ProfilingTask{}, []api.ProcessInterface{p}); err != nil {
		return err
	}

	if err := runner.Run(ctx, func() {
		_ = runner.Stop()
	}); err != nil {
		return err
	}

	return nil
}

func writeOutput(data *outputData, file io.Writer, format string) {
	if format != "json" {
		sprintData := fmt.Sprintf("Kernel: %s\nStartup: %s\nOnCPU: %s\nOffCPU: %s\nNetwork: %s",
			data.Kernel, errorOrSuccess(data.Startup), errorOrSuccess(data.OnCPU),
			errorOrSuccess(data.OffCPU), errorOrSuccess(data.Network))
		_, _ = file.Write([]byte(sprintData))
		return
	}
	// some error could not be marshaled, such as multierror
	jsonData := &outputDataJSON{
		Kernel:  data.Kernel,
		Startup: errorOrSuccess(data.Startup),
		OnCPU:   errorOrSuccess(data.OnCPU),
		OffCPU:  errorOrSuccess(data.OffCPU),
		Network: errorOrSuccess(data.Network),
	}
	marshal, err := json.Marshal(jsonData)
	if err != nil {
		log.Printf("format the output failure: %v", err)
		return
	}
	_, _ = file.Write(marshal)
}

func errorOrSuccess(data error) string {
	if data != nil {
		return data.Error()
	}
	return "true"
}

type outputData struct {
	Kernel  string
	Startup error
	OnCPU   error
	OffCPU  error
	Network error
}

type outputDataJSON struct {
	Kernel  string
	Startup string
	OnCPU   string
	OffCPU  string
	Network string
}
