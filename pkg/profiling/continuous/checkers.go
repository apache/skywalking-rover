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

package continuous

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/apache/skywalking-rover/pkg/core"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/process"
	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/base"
	"github.com/apache/skywalking-rover/pkg/profiling/continuous/checker"

	profilingv3 "skywalking.apache.org/repo/goapi/collect/ebpf/profiling/v3"
	meterv3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"

	"github.com/hashicorp/go-multierror"
)

var checkerRegistration = make([]base.Checker, 0)

func init() {
	checkerRegistration = append(checkerRegistration,
		// system
		checker.NewSystemLoadChecker(),
		// process
		checker.NewProcessCPUChecker(),
		checker.NewProcessThreadCountChecker(),
		// network
		checker.NewNetworkResponseErrorChecker(),
		checker.NewNetworkAvgResponseTimeChecker())
}

type Checkers struct {
	meterPrefix     string
	fetchDuration   time.Duration
	checkDuration   time.Duration
	processOperator process.Operator
	triggers        *Triggers
	policiesCache   map[string]*base.ServicePolicy

	meterClient      meterv3.MeterReportServiceClient
	continuousClient profilingv3.ContinuousProfilingServiceClient
	ctx              context.Context
}

func NewCheckers(ctx context.Context, moduleMgr *module.Manager, conf *base.ContinuousConfig, triggers *Triggers) (*Checkers, error) {
	connection := moduleMgr.FindModule(core.ModuleName).(core.Operator).BackendOperator().GetConnection()
	meterClient := meterv3.NewMeterReportServiceClient(connection)
	continuousClient := profilingv3.NewContinuousProfilingServiceClient(connection)

	if conf.MeterPrefix == "" {
		return nil, fmt.Errorf("the continuous profiling meter prefix cannot be empty")
	}

	fetchDuration, err := time.ParseDuration(conf.FetchInterval)
	if err != nil {
		return nil, fmt.Errorf("fetch duration error: %v", err)
	}
	checkDuration, err := time.ParseDuration(conf.CheckInterval)
	if err != nil {
		return nil, fmt.Errorf("check duration error: %v", err)
	}

	for _, checker := range checkerRegistration {
		if e := checker.Init(conf); e != nil {
			err = multierror.Append(err, e)
		}
	}
	if err != nil {
		return nil, err
	}

	return &Checkers{
		meterClient:      meterClient,
		continuousClient: continuousClient,
		meterPrefix:      conf.MeterPrefix,
		fetchDuration:    fetchDuration,
		checkDuration:    checkDuration,
		processOperator:  moduleMgr.FindModule(process.ModuleName).(process.Operator),
		triggers:         triggers,
		policiesCache:    make(map[string]*base.ServicePolicy),
		ctx:              ctx,
	}, nil
}

func (c *Checkers) Start() {
	// starting to check the threshold with interval
	go func() {
		fetchTicker := time.NewTicker(c.fetchDuration)
		checkTicker := time.NewTicker(c.checkDuration)
		for {
			select {
			case <-fetchTicker.C:
				if err := c.fetchAllData(); err != nil {
					log.Errorf("fetch all data error: %v", err)
				}
			case <-checkTicker.C:
				c.checkAllThresholds()
			case <-c.ctx.Done():
				checkTicker.Stop()
				return
			}
		}
	}()
}

func (c *Checkers) Stop() error {
	var err error
	for _, checker := range checkerRegistration {
		if e := checker.Close(); e != nil {
			err = multierror.Append(err, e)
		}
	}
	return err
}

func (c *Checkers) CheckProfilingPolicies() error {
	// fetch and update the policies
	if hasUpdate, err := c.updatePolicyCache(); err != nil {
		return err
	} else if !hasUpdate {
		return nil
	}

	// synchronized to all checkers
	policiesWithProcesses := make([]*base.SyncPolicyWithProcesses, 0)
	for _, servicePolicy := range c.policiesCache {
		for _, policy := range servicePolicy.Policies {
			policiesWithProcesses = append(policiesWithProcesses, &base.SyncPolicyWithProcesses{
				Policy:    policy,
				Processes: servicePolicy.Processes,
			})
		}
	}
	for _, checker := range checkerRegistration {
		checker.SyncPolicies(policiesWithProcesses)
	}
	return nil
}

func (c *Checkers) fetchAllData() error {
	var err error
	for _, checker := range checkerRegistration {
		if e := checker.Fetch(); e != nil {
			err = multierror.Append(err, e)
		}
	}
	return err
}

func (c *Checkers) checkAllThresholds() {
	// check all thresholds and send metrics
	metricsAppender := base.NewMetricsAppender(c.meterPrefix)
	causes := c.findAllMatchCauses(metricsAppender)
	if e := metricsAppender.Flush(c.ctx, c.meterClient); e != nil {
		log.Warnf("flush the checker metrics failure: %v", e)
	}
	if len(causes) == 0 {
		return
	}

	c.triggers.handleCauses(causes)
}

func (c *Checkers) findAllMatchCauses(appender *base.MetricsAppender) []base.ThresholdCause {
	causes := make([]base.ThresholdCause, 0)
	for _, checker := range checkerRegistration {
		overThresholds := checker.Check(c, appender)
		if len(overThresholds) == 0 {
			continue
		}

		causes = append(causes, overThresholds...)
	}

	return causes
}

func (c *Checkers) ShouldCheck(p api.ProcessInterface, item *base.PolicyItem) bool {
	profilingType := item.Policy.TargetProfilingType
	trigger := triggerRegistration[profilingType]
	return trigger.ShouldTrigger(p)
}

func (c *Checkers) updatePolicyCache() (bool, error) {
	processes := c.processOperator.FindAllRegisteredProcesses()
	if len(processes) == 0 {
		// if existing policies, then clean it
		if (len(c.policiesCache)) > 0 {
			c.policiesCache = make(map[string]*base.ServicePolicy)
			return true, nil
		}
		return false, nil
	}

	serviceProcesses := make(map[string]map[string]api.ProcessInterface)

	// get all existing service and policy UUID mapping
	servicePolicyUUIDCache := make(map[string]string, 0)
	for _, p := range processes {
		serviceName := p.Entity().ServiceName
		cachedPolicy := c.policiesCache[serviceName]
		if cachedPolicy != nil {
			servicePolicyUUIDCache[serviceName] = cachedPolicy.UUID
		} else {
			servicePolicyUUIDCache[serviceName] = ""
		}

		// build the service process
		serviceProcessesMap := serviceProcesses[serviceName]
		if serviceProcessesMap == nil {
			serviceProcessesMap = make(map[string]api.ProcessInterface)
			serviceProcesses[serviceName] = serviceProcessesMap
		}
		serviceProcessesMap[p.ID()] = p
	}

	policiesUpdates, err := c.queryPolicyUpdates(servicePolicyUUIDCache)
	if err != nil {
		return false, err
	}
	hasUpdate := false
	for serviceName, policy := range policiesUpdates {
		existingPolicy := c.policiesCache[serviceName]
		// update cache if the service policy not exist or UUID are not same
		if existingPolicy == nil || existingPolicy.UUID != policy.UUID {
			existingPolicy = policy
			c.policiesCache[serviceName] = policy
			hasUpdate = true
		}
		// update the processes if they are not same
		if !c.checkProcessesAreSame(existingPolicy.Processes, serviceProcesses[serviceName]) {
			hasUpdate = true
			existingPolicy.Processes = serviceProcesses[serviceName]
		}
	}
	return hasUpdate, nil
}

func (c *Checkers) checkProcessesAreSame(from, target map[string]api.ProcessInterface) bool {
	if len(from) != len(target) {
		return false
	}

	// all process id have same pid
	for processID, targetProcess := range target {
		if fromProcess := from[processID]; fromProcess == nil {
			return false
		} else if fromProcess.Pid() != targetProcess.Pid() {
			return false
		}
	}

	return true
}

func (c *Checkers) queryPolicyUpdates(servicePolicies map[string]string) (map[string]*base.ServicePolicy, error) {
	queries := make([]*profilingv3.ContinuousProfilingServicePolicyQuery, 0)
	for k, v := range servicePolicies {
		queries = append(queries, &profilingv3.ContinuousProfilingServicePolicyQuery{
			ServiceName: k,
			Uuid:        v,
		})
	}
	policyUpdateCommands, err := c.continuousClient.QueryPolicies(c.ctx, &profilingv3.ContinuousProfilingPolicyQuery{Policies: queries})
	if err != nil {
		return nil, err
	}
	// no update
	if len(policyUpdateCommands.GetCommands()) == 0 {
		return nil, nil
	}

	var policyJSON string
	if len(policyUpdateCommands.GetCommands()) == 1 && policyUpdateCommands.GetCommands()[0].GetCommand() == "ContinuousProfilingPolicyQuery" {
		for _, arg := range policyUpdateCommands.GetCommands()[0].GetArgs() {
			if arg.GetKey() == "ServiceWithPolicyJSON" {
				policyJSON = arg.GetValue()
				break
			}
		}
	}
	if policyJSON == "" {
		return nil, fmt.Errorf("the query policy response not adapt")
	}

	updates := make([]*QueryPolicyUpdate, 0)
	err = json.Unmarshal([]byte(policyJSON), &updates)
	if err != nil {
		return nil, fmt.Errorf("error to unmarshal the policy updates: %v", err)
	}

	result := make(map[string]*base.ServicePolicy)
	for _, update := range updates {
		servicePolicy := &base.ServicePolicy{
			Service: update.ServiceName,
			UUID:    update.UUID,
		}
		for profilingType, checks := range update.Profiling {
			policy := &base.Policy{
				TargetProfilingType: profilingType,
				Items:               make(map[base.CheckType]*base.PolicyItem),
				ServicePolicy:       servicePolicy,
			}

			for checkType, item := range checks {
				if err := item.Validate(); err != nil {
					log.Warnf("cannot add the policy item, service name: %s, profiling type: %s, policy type: %s, error: %v",
						update.ServiceName, profilingType, checkType, err)
					continue
				}
				policy.Items[checkType] = &base.PolicyItem{
					Threshold: item.Threshold,
					Period:    item.Period,
					Count:     item.Count,
					URIList:   item.URIList,
					URIRegex:  item.URIRegex,
					Policy:    policy,
				}
			}

			servicePolicy.Policies = append(servicePolicy.Policies, policy)
		}

		result[update.ServiceName] = servicePolicy
	}
	return result, nil
}

type QueryPolicyUpdate struct {
	ServiceName string `json:"ServiceName"`
	UUID        string `json:"UUID"`
	Profiling   map[base.TargetProfilingType]map[base.CheckType]*QueryPolicyUpdateItem
}

type QueryPolicyUpdateItem struct {
	Threshold string   `json:"Threshold"`
	Period    int      `json:"Period"`
	Count     int      `json:"Count"`
	URIList   []string `json:"URIList"`
	URIRegex  string   `json:"URIRegex"`
}

func (p *QueryPolicyUpdateItem) Validate() error {
	if p.Threshold == "" {
		return fmt.Errorf("thrshold cannot be empty")
	}
	if p.Period <= 0 {
		return fmt.Errorf("period cannot smaller or equals zero")
	}
	if p.Count <= 0 {
		return fmt.Errorf("count cannot smaller or equals zero")
	}
	if p.Count > p.Period {
		return fmt.Errorf("count cannot be bigger than period")
	}
	return nil
}
