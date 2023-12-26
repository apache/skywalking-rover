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
set -ex

VERSION=$1

echo "ready to generate the offset of nodejs $VERSION"

current_dir="$(cd "$(dirname $0)"; pwd)"
WORK_DIR="$current_dir/nodejs"
ROVER_DIR="$current_dir/../../"

# download source code
mkdir -p $WORK_DIR && cd $WORK_DIR
wget -O node.tar.gz https://github.com/nodejs/node/archive/$VERSION.tar.gz
tar -xf node.tar.gz --strip 1 && rm node.tar.gz

# compile as the debug binary file
./configure --debug && make -j8
NODE_PATH="$WORK_DIR/out/Debug/node"

# generate ssl certs and start https server
bash $ROVER_DIR/test/e2e/base/scripts/gen-selfsigned-ssl.sh service $ROVER_DIR/test/e2e/cases/profiling/network/base/ssl/
$NODE_PATH

# run the go program
cd $ROVER_DIR
go run scripts/debug/node_tls_gen_offsets.go $NODE_PATH