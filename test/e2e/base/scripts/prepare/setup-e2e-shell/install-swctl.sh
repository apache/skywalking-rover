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
  # Do not rely on the cli Makefile's own install copy: it is prefixed with `-`, so make ignores
  # a failed copy and an unwritable ${BIN_DIR} "succeeds" with no swctl installed. Pin
  # VERSION/GOOS/GOARCH so its output path bin/$(BINARY)-$(VERSION)-$(GOOS)-$(GOARCH) is exact,
  # and copy that. VERSION is the pinned commit because the tarball has no .git to read.
  swctl_os=$(go env GOOS)
  swctl_arch=$(go env GOARCH)
  swctl_built="bin/swctl-${SW_CTL_COMMIT}-${swctl_os}-${swctl_arch}"
  make install DESTDIR=$BIN_DIR VERSION=${SW_CTL_COMMIT} GOOS=${swctl_os} GOARCH=${swctl_arch}
  if [ ! -f "${swctl_built}" ]; then
    echo "install-swctl: expected ${swctl_built} to be built, but it is missing" >&2
    ls -la bin >&2 || true
    exit 1
  fi
  # ${BASE_DIR}/bin is on the infra-e2e PATH and must succeed; ${BIN_DIR} is best effort.
  mkdir -p $BASE_DIR/bin
  cp "${swctl_built}" $BASE_DIR/bin/swctl
  chmod +x $BASE_DIR/bin/swctl
  cp "${swctl_built}" $BIN_DIR/swctl 2>/dev/null && chmod +x $BIN_DIR/swctl || \
    echo "install-swctl: ${BIN_DIR} is not writable, using ${BASE_DIR}/bin/swctl only" >&2
fi