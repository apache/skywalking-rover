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

package common //nolint:revive // package name is acceptable in this context

import (
	"regexp"
	"strings"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/checker/bpf/network"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
)

type HTTPBasedChecker struct {
	*BaseChecker[*HTTPBasedCheckerProcessInfo]

	CheckType         base.CheckType
	MonitorType       v3.ContinuousProfilingTriggeredMonitorType
	ThresholdGenerate func(val string) (float64, error)
}

func NewHTTPBasedChecker(checkType base.CheckType,
	thresholdGenerator func(val string) (float64, error), dataGenerator func() base.WindowData[network.BufferEvent, float64],
	monitorType v3.ContinuousProfilingTriggeredMonitorType) *HTTPBasedChecker {
	checker := &HTTPBasedChecker{
		CheckType:         checkType,
		ThresholdGenerate: thresholdGenerator,
		MonitorType:       monitorType,
	}
	checker.BaseChecker = NewBaseChecker[*HTTPBasedCheckerProcessInfo](
		func(p api.ProcessInterface, older *HTTPBasedCheckerProcessInfo, items []*base.PolicyItem) *HTTPBasedCheckerProcessInfo {
			result := &HTTPBasedCheckerProcessInfo{
				Process:           p,
				PolicyWithWindows: make(map[*base.PolicyItem]*HTTPBasedCheckerPolicyItemWindows),
			}
			for _, item := range items {
				val, _ := thresholdGenerator(item.Threshold)
				policyInfo := &HTTPBasedCheckerPolicyItemWindows{
					threshold: val,
				}

				timeWindowsUpdated := false
				if older != nil {
					for olderItem, olderInfo := range older.PolicyWithWindows {
						// reading from the older policy info
						if olderItem.SameURIFilter(item) {
							if len(item.URIList) > 0 {
								for _, w := range olderInfo.uriWithTimeWindows {
									w.ScalePeriod([]*base.PolicyItem{item})
								}

								policyInfo.uriWithTimeWindows = olderInfo.uriWithTimeWindows
							} else {
								policyInfo.defaultTimeWindows = olderInfo.defaultTimeWindows
								policyInfo.defaultTimeWindows.ScalePeriod([]*base.PolicyItem{item})
							}
							timeWindowsUpdated = true
							break
						}
					}
				}

				if timeWindowsUpdated {
					result.PolicyWithWindows[item] = policyInfo
					continue
				}

				// otherwise, create the time windows
				if len(item.URIList) > 0 {
					uriWithWindows := make(map[string]*base.TimeWindows[network.BufferEvent, float64])
					for _, uri := range item.URIList {
						uriWithWindows[uri] = base.NewTimeWindows[network.BufferEvent, float64](
							[]*base.PolicyItem{item}, func() base.WindowData[network.BufferEvent, float64] {
								return dataGenerator()
							})
					}
					policyInfo.uriWithTimeWindows = uriWithWindows
				} else if item.URIRegex != "" {
					regex, err := regexp.Compile(item.URIRegex)
					if err != nil {
						log.Warnf("error to compile the URI regex for policy, ignore this policy. regex: %s", item.URIRegex)
						continue
					}
					policyInfo.uriRegex = regex
				}
				policyInfo.defaultTimeWindows = base.NewTimeWindows[network.BufferEvent, float64](
					[]*base.PolicyItem{item}, func() base.WindowData[network.BufferEvent, float64] {
						return dataGenerator()
					})

				result.PolicyWithWindows[item] = policyInfo
			}
			return result
		})
	network.AddEventNotify(checker)
	return checker
}

func (n *HTTPBasedChecker) SyncPolicies(policies []*base.SyncPolicyWithProcesses) {
	n.BaseChecker.SyncPolicies(policies, func(items map[base.CheckType]*base.PolicyItem) *base.PolicyItem {
		item := items[n.CheckType]
		if item == nil {
			return nil
		}
		_, err := n.ThresholdGenerate(item.Threshold)
		if err != nil {
			log.Warnf("failure to parse the %s threshold to int: %v", n.CheckType, item.Threshold)
			return nil
		}
		return item
	}, func(pid int32, isDelete bool) {
		// notify to the listener
		var err error
		defer func() {
			if err != nil {
				log.Warnf("process the pid monitoring failure, pid: %d, is delete: %t, erro: %v", pid, isDelete, err)
			}
		}()
		if isDelete {
			err = network.RemoveWatchProcess(pid, string(n.CheckType))
			return
		}

		err = network.AddWatchProcess(pid, string(n.CheckType))
	})
}

func (n *HTTPBasedChecker) ReceiveBufferEvent(event network.BufferEvent) {
	info := n.PidWithInfos[event.Pid()]
	if info == nil {
		return
	}

	for _, policyInfo := range info.PolicyWithWindows {
		var matchesWindows *base.TimeWindows[network.BufferEvent, float64]
		// match with the regex or URI list
		if len(policyInfo.uriWithTimeWindows) > 0 {
			for uri, windows := range policyInfo.uriWithTimeWindows {
				if event.RequestURI() == uri {
					matchesWindows = windows
				}
			}
			if matchesWindows == nil {
				continue
			}
		} else if policyInfo.uriRegex != nil && !policyInfo.uriRegex.MatchString(event.RequestURI()) {
			continue
		}

		if matchesWindows == nil {
			matchesWindows = policyInfo.defaultTimeWindows
		}

		matchesWindows.Add(event.StartTime(), event)
	}
}

func (n *HTTPBasedChecker) Fetch() error {
	return nil
}

func (n *HTTPBasedChecker) Close() error {
	return network.ForceShutdownBPF()
}

func (n *HTTPBasedChecker) Check(ctx base.CheckContext, metricsAppender *base.MetricsAppender) []base.ThresholdCause {
	causes := make([]base.ThresholdCause, 0)
	for _, pidPolicies := range n.PidWithInfos {
		for item, itemInfo := range pidPolicies.PolicyWithWindows {
			globalURI := ""
			if itemInfo.uriRegex != nil {
				globalURI = itemInfo.uriRegex.String()
			}
			for uri, windows := range itemInfo.uriWithTimeWindows {
				n.flushMetrics(uri, windows, pidPolicies.Process, metricsAppender)
			}
			if itemInfo.defaultTimeWindows != nil {
				n.flushMetrics(globalURI, itemInfo.defaultTimeWindows, pidPolicies.Process, metricsAppender)
			}
			if !ctx.ShouldCheck(pidPolicies.Process, item) {
				continue
			}

			// url list checker
			for uri, window := range itemInfo.uriWithTimeWindows {
				if lastMatch, isMatch := window.MatchRule(item, func(val float64) bool {
					return val >= itemInfo.threshold
				}); isMatch {
					causes = append(causes, NewURICause(pidPolicies.Process, false, uri, item,
						n.MonitorType, itemInfo.threshold, lastMatch))
				}
			}

			// regex or global
			if lastMatch, isMatch := itemInfo.defaultTimeWindows.MatchRule(item, func(val float64) bool {
				return val >= itemInfo.threshold
			}); isMatch {
				causes = append(causes, NewURICause(pidPolicies.Process, itemInfo.uriRegex != nil, globalURI, item,
					n.MonitorType, itemInfo.threshold, lastMatch))
			}
		}
	}
	return causes
}

func (n *HTTPBasedChecker) flushMetrics(uri string, windows *base.TimeWindows[network.BufferEvent, float64],
	process api.ProcessInterface, metricsAppender *base.MetricsAppender) {
	if uri == "" {
		uri = "global"
	}
	if data, hasUpdate := windows.FlushMultipleRecentData(); hasUpdate {
		// flush each slot data
		for _, d := range data {
			metricsAppender.AppendProcessSingleValue(strings.ToLower(string(n.CheckType)), process, map[string]string{
				"uri": uri,
			}, d)
		}
	}
}

type HTTPBasedCheckerProcessInfo struct {
	Process           api.ProcessInterface
	PolicyWithWindows map[*base.PolicyItem]*HTTPBasedCheckerPolicyItemWindows
}

type HTTPBasedCheckerPolicyItemWindows struct {
	uriWithTimeWindows map[string]*base.TimeWindows[network.BufferEvent, float64]

	uriRegex           *regexp.Regexp
	defaultTimeWindows *base.TimeWindows[network.BufferEvent, float64]

	threshold float64
}
