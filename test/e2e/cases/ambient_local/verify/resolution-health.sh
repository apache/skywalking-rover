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

# Regression guard for the ambient remote address resolution. Rover periodically logs a
# "remote address resolve summary" with how many remote addresses it resolved through the
# ztunnel inbound/outbound correlation versus how many stayed unresolved and were sent as a
# raw IP. On the ambient data path the conntrack(netlink) lookup is essentially always empty,
# so the ztunnel correlation MUST carry the resolution: if it regresses, every ClusterIP hop
# degrades to a raw IP node and the topology silently loses its shape. Both checks flip to
# false in that case.
#
# NOTE: uses grep -c/-oE(which read all of the input) rather than grep -q, see the sibling
# ztunnel-binding.sh for why.
set -e

pod=$(kubectl get pod -l name=skywalking-rover -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
line=$(kubectl logs "${pod}" --tail=-1 2>/dev/null | grep -a 'remote address resolve summary' | tail -1)

printf '%s\n' "${line}" >&2

# both numbers are read as CUMULATIVE totals so the comparison below compares like with
# like: the summary reports the unresolved count twice, "since last report" and
# "(cumulative total: N)", and pairing an interval count against a cumulative one would
# make the majority check pass trivially.
ztunnel=$(printf '%s' "${line}" | grep -oE 'resolved by ztunnel correlation\(cumulative\): [0-9]+' | grep -oE '[0-9]+$' | tail -1)
unresolved=$(printf '%s' "${line}" | grep -oE 'cumulative total: [0-9]+' | grep -oE '[0-9]+$' | tail -1)
ztunnel=${ztunnel:-0}
unresolved=${unresolved:-0}
printf 'ztunnel resolved(cumulative): %s ; unresolved(cumulative): %s\n' "${ztunnel}" "${unresolved}" >&2

# the ztunnel correlation actually resolved remote addresses
if [ "${ztunnel}" -gt 0 ]; then
  echo "ztunnel_resolution_active: true"
else
  echo "ztunnel_resolution_active: false"
fi
# and it resolves the majority - a broken data path leaves everything unresolved
if [ "${ztunnel}" -ge "${unresolved}" ]; then
  echo "resolution_dominant: true"
else
  echo "resolution_dominant: false"
fi
