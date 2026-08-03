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

set -ex

BASE_DIR=$1
BIN_DIR=$2

# Fail loudly on a missing argument or version instead of silently deriving a path from an
# empty variable - an unset BASE_DIR would otherwise turn the mkdir below into "/istioctl",
# and an unset ISTIO_VERSION would make the downloader pick whatever it considers latest.
if [ -z "$BASE_DIR" ] || [ -z "$BIN_DIR" ]; then
  echo "usage: $0 <base-dir> <bin-dir>  (got BASE_DIR='$BASE_DIR' BIN_DIR='$BIN_DIR')" >&2
  exit 1
fi
if [ -z "$ISTIO_VERSION" ]; then
  echo "ISTIO_VERSION must be set: the cases are parameterized by istio version" >&2
  exit 1
fi

# Always fetch the pinned ${ISTIO_VERSION} rather than keeping a pre-existing istioctl that
# happens to be on PATH. The cases are parameterized by istio version, so a leftover binary
# of a different version silently installs the wrong control plane - and a pre-1.24 istioctl
# does not even ship the ambient profile, failing with
# "Asset profiles/ambient.yaml not found".
mkdir -p "$BASE_DIR/istioctl" && cd "$BASE_DIR/istioctl"
curl -sL https://istio.io/downloadIstio | ISTIO_VERSION="$ISTIO_VERSION" sh -
cp "istio-$ISTIO_VERSION/bin/istioctl" "$BIN_DIR/istioctl"

# The cases prepend ${BASE_DIR}/bin to PATH, so an istioctl sitting THERE shadows the one
# just installed into ${BIN_DIR} - a leftover from an earlier run would silently defeat the
# version pin and install a different istio than the case asked for. Write the pinned binary
# to that directory too, so the first match on PATH is always the right version.
mkdir -p "$BASE_DIR/bin"
cp "istio-$ISTIO_VERSION/bin/istioctl" "$BASE_DIR/bin/istioctl"

"$BIN_DIR/istioctl" version --remote=false || true
