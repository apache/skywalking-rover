#!/bin/bash

#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# the rover config file
config_file=$1
# the demo program file
demo_exe_file=$2
# the skywalking rover binary file
rover_exe_file=$3
# the checker output directory
output_dir=$4
# the output format, support: json, plain
output_format=$5

set -e

mkdir -p $output_dir

# build and run demo program
nohup $demo_exe_file >/dev/null 2>&1 &
sleep 1

# run checker
set +e
nohup $rover_exe_file check -c $config_file -o "$output_dir/result.txt" -f $output_format > "$output_dir/checker.log" 2>&1
set -e

# close the demo program
kill -9 `pidof $demo_exe_file`