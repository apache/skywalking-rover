#!/bin/bash
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Assert SOMETHING is producing the ambient connection identities, without pinning which of
# the redundant sources it is. Rover reads a connection's identity either from ztunnel memory
# through the ConnectionResult::record_internal uprobe(the default) or - when that uprobe
# cannot attach or decode on a given ztunnel build - by tailing ztunnel's own access log.
#
# The two sources are mutually exclusive BY DESIGN: the tailer is only started once the uprobe
# path has been ruled out, so asserting "the access log tailer parsed lines" would fail on
# every ztunnel whose symbols DO resolve, and asserting "the uprobe is decoding" would fail on
# every ztunnel where they do not. What must hold on any ztunnel build is that one of them is
# alive and producing identities, which is what this checks.
#
# The per-source detail goes to stderr so the e2e log records WHICH path a given istio version
# actually took.
#
# NOTE: uses grep -c/-oE(which read all of the input) rather than grep -q, see the sibling
# ztunnel-binding.sh for why.
set -e

pod=$(kubectl get pod -l name=skywalking-rover -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
logs=$(kubectl logs "${pod}" --tail=-1 2>/dev/null || true)

cnt() { printf '%s\n' "${logs}" | grep -acE "$1" || true; }

# the identity uprobe reached the active state and decoded identities out of ztunnel memory
uprobe_decoding=no
[ "$(cnt 'identity uprobe: \{state: active, events: [0-9]+, decoded: [1-9]')" -gt 0 ] && uprobe_decoding=yes

# the access log tailer is live and parsing ztunnel's "connection complete" lines
parsed=$(printf '%s\n' "${logs}" \
  | grep -aoE "access_log lines parsed\(fallback live\): [0-9]+" \
  | grep -oE "[0-9]+$" | sort -n | tail -1)
parsed=${parsed:-0}

# evidence for the record
printf 'identity uprobe decoding: %s ; access_log lines parsed: %s\n' "${uprobe_decoding}" "${parsed}" >&2
printf '%s\n' "${logs}" | grep -aoE "identity uprobe: \{[^}]*\}" | tail -1 >&2 || true
printf '%s\n' "${logs}" | grep -aoE "identity additions: \{[^}]*\}" | tail -1 >&2 || true

if [ "${uprobe_decoding}" = yes ] || [ "${parsed}" -gt 0 ]; then
  echo "identity_source_producing: true"
else
  echo "identity_source_producing: false"
fi
