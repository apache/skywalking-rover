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
	"github.com/spf13/cobra"

	"github.com/apache/skywalking-rover/pkg/license"
)

func newDependencyCheckCmd() *cobra.Command {
	configPath := ""
	licensePath := ""
	licenseOutDir := ""
	cmd := &cobra.Command{
		Use:   "license",
		Short: "generate the dependency license",
		RunE: func(cmd *cobra.Command, args []string) error {
			return license.GenerateDependencyLicense(configPath, licensePath, licenseOutDir)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "configs/license_config.yaml", "the rover license config file path")
	cmd.Flags().StringVarP(&licensePath, "license", "l", "dist/LICENSE", "the license file path")
	cmd.Flags().StringVarP(&licenseOutDir, "output", "o", "dist/licenses", "the dependency license output directory path")
	return cmd
}
