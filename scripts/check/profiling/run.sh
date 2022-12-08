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
set -e

current_dir="$(cd "$(dirname $0)"; pwd)"
ROVER_DIR="$current_dir/../../../"

# build demo program
echo "building demo program"
go build demo.go
mv demo ./demo-program

# build the skywalking rover
echo "builing skywalking rover"
make -C $ROVER_DIR container-generate build
cp $ROVER_DIR/bin/skywalking-rover-latest-linux-amd64 ./skywalking-rover

# run the checker
echo "running checker"
bash check.sh $current_dir/config.yaml $current_dir/demo-program $current_dir/skywalking-rover "$current_dir/output"
echo "check result:"
echo "---------------------------------"
cat "$current_dir/output"