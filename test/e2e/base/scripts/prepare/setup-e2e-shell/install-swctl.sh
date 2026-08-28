#!/usr/bin/env bash

# ----------------------------------------------------------------------------
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# ----------------------------------------------------------------------------

set -e

BASE_DIR=$1
BIN_DIR=$2

if ! command -v swctl &> /dev/null; then
  mkdir -p $BASE_DIR/swctl && cd $BASE_DIR/swctl
  curl -kLo skywalking-cli.tar.gz https://github.com/apache/skywalking-cli/archive/${SW_CTL_COMMIT}.tar.gz
  tar -zxf skywalking-cli.tar.gz --strip=1
  # skywalking-cli's `install` target prefixes its copy with `-`, so make IGNORES a failed copy:
  # on a runner where ${BIN_DIR}(/usr/local/bin) is not writable, this step still prints
  # "success to install swctl" while no swctl exists, and every swctl based verify case then
  # retries until it times out with nothing in the log pointing at the cause. Install the built
  # binary into ${BASE_DIR}/bin as well - the dir infra-e2e prepends to PATH, and one this script
  # always owns - and fail loudly if no binary was produced at all.
  make install DESTDIR=$BIN_DIR
  mkdir -p $BASE_DIR/bin
  cp bin/swctl-* $BASE_DIR/bin/swctl
  chmod +x $BASE_DIR/bin/swctl
fi