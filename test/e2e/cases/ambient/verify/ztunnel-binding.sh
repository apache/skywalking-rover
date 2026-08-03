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

# Assert rover actually correlates BOTH legs of the ambient(ztunnel) data path: it tags
# the ztunnel INBOUND leg(the ztunnel -> workload connection) and the uprobe delivers the
# OUTBOUND load balanced socket mappings. Prints a "<check>: true/false" line per leg.
#
# The evidence is read from the periodic INFO level "ztunnel correlation stats" line rather
# than from per-event debug logs: enabling the ztunnel module at DEBUG floods the event hot
# path and delays the mapping cache enough to leave connections unresolved. The stats line
# already carries "inbound legs tagged: N" and "uprobe mapping events received: N".
#
# NOTE: do NOT use `set -o pipefail` together with `grep -q` here. The agent log is multi-MB;
# `grep -q` exits on the first match and closes the pipe, the upstream writer then gets
# SIGPIPE and pipefail would report a found match as a failed pipeline. Count with `grep -c`,
# which reads all of the input.
set -e

pod=$(kubectl get pod -l name=skywalking-rover -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
logs=$(kubectl logs "${pod}" --tail=-1 2>/dev/null || true)

emit() {
  local key="$1" pattern="$2" count
  count=$(printf '%s\n' "${logs}" | grep -acE "${pattern}" || true)
  if [ "${count:-0}" -gt 0 ]; then echo "${key}: true"; else echo "${key}: false"; fi
}

# surface the latest stats line into the e2e log(stderr, so it does not affect the match)
printf '%s\n' "${logs}" | grep -aoE "ztunnel correlation stats: .*" | tail -1 >&2 || true

emit inbound_leg_tagged "inbound legs tagged: [1-9]"
emit outbound_mapping_observed "uprobe mapping events received: [1-9]"
