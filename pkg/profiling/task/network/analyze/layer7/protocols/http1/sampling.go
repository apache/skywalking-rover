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

package http1

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"

	"github.com/apache/skywalking-rover/pkg/process/api"
	profiling "github.com/apache/skywalking-rover/pkg/profiling/task/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	protocol "github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/layer7/protocols/metrics"
)

const (
	TopNSize              = 10
	SamplingRuleCacheSize = 200
)

type Sampler struct {
	Error4xxTraces *metrics.TopN
	Error5xxTraces *metrics.TopN
	SlowTraces     *metrics.TopN
}

func NewSampler() *Sampler {
	return &Sampler{
		Error4xxTraces: metrics.NewTopN(TopNSize),
		Error5xxTraces: metrics.NewTopN(TopNSize),
		SlowTraces:     metrics.NewTopN(TopNSize),
	}
}

func (s *Sampler) AppendMetrics(config *SamplingConfig, duration time.Duration,
	request *http.Request, response *http.Response, reqBuffer, respBuffer protocol.SocketDataBuffer) {
	if config == nil {
		return
	}
	tracingContext, err := protocol.AnalyzeTracingContext(func(key string) string {
		return request.Header.Get(key)
	})
	if err != nil {
		log.Warnf("analyze tracing context error: %v", err)
		return
	}
	if tracingContext == nil {
		return
	}

	uri := request.RequestURI
	// remove the query parameters
	if i := strings.Index(uri, "?"); i > 0 {
		uri = uri[0:i]
	}

	// find out with url rule is match
	rule := config.findMatchesRule(uri)
	if rule == nil {
		return
	}

	// if smaller than minimal duration, then ignore
	if int64(rule.MinDuration) > duration.Milliseconds() {
		return
	}

	var traceType string
	var topN *metrics.TopN
	if rule.When5XX && response.StatusCode >= 500 && response.StatusCode < 600 {
		traceType = "status_5xx"
		topN = s.Error5xxTraces
	} else if rule.When4XX && response.StatusCode >= 400 && response.StatusCode < 500 {
		traceType = "status_4xx"
		topN = s.Error4xxTraces
	} else {
		traceType = "slow"
		topN = s.SlowTraces
	}

	trace := &Trace{
		Trace:          tracingContext,
		RequestURI:     uri,
		RequestBuffer:  reqBuffer,
		ResponseBuffer: respBuffer,
		Request:        request,
		Response:       response,
		Type:           traceType,
		Settings:       rule.Settings,
	}
	topN.AddRecord(trace, duration.Milliseconds())
}

func (s *Sampler) BuildMetrics(process api.ProcessInterface, traffic *base.ProcessTraffic, metricsBuilder *base.MetricsBuilder) int {
	var count int
	count += s.SlowTraces.AppendData(process, traffic, metricsBuilder)
	count += s.Error4xxTraces.AppendData(process, traffic, metricsBuilder)
	count += s.Error5xxTraces.AppendData(process, traffic, metricsBuilder)
	return count
}

func (s *Sampler) MergeAndClean(other *Sampler) {
	s.SlowTraces.MergeAndClean(other.SlowTraces)
	s.Error4xxTraces.MergeAndClean(other.Error4xxTraces)
	s.Error5xxTraces.MergeAndClean(other.Error5xxTraces)
}

func (s *Sampler) String() string {
	return fmt.Sprintf("slow trace count: %d, 4xx error count: %d, 5xx error count: %d",
		s.SlowTraces.List.Len(), s.Error4xxTraces.List.Len(), s.Error5xxTraces.List.Len())
}

type SamplingConfig struct {
	DefaultRule  *profiling.NetworkSamplingRule
	URISamplings []*URISampling
	uriRuleCache *lru.Cache
}

type URISampling struct {
	URIMatcher *regexp.Regexp
	Rule       *profiling.NetworkSamplingRule
}

func NewSamplingConfig(configs []*profiling.NetworkSamplingRule) *SamplingConfig {
	if len(configs) == 0 {
		return nil
	}
	cache, err := lru.New(SamplingRuleCacheSize)
	if err != nil {
		log.Warnf("creating sampling cache config failure: %v", err)
	}
	result := &SamplingConfig{
		uriRuleCache: cache,
	}
	for _, c := range configs {
		if c.URIRegex == nil {
			if result.DefaultRule != nil {
				log.Warnf("the default rule is already exists, so ignore it")
				continue
			}
			result.DefaultRule = c
			continue
		}

		uriPattern, err := regexp.Compile(*c.URIRegex)
		if err != nil {
			log.Warnf("parsing URI pattern failure, ignore this sampling config: %v", err)
			continue
		}

		result.URISamplings = append(result.URISamplings, &URISampling{
			URIMatcher: uriPattern,
			Rule:       c,
		})
	}
	return result
}

func (s *SamplingConfig) findMatchesRule(uri string) *profiling.NetworkSamplingRule {
	// if cached then return
	if len(s.URISamplings) == 0 {
		return s.DefaultRule
	}

	value, ok := s.uriRuleCache.Get(uri)
	if ok {
		return value.(*profiling.NetworkSamplingRule)
	}

	result := s.DefaultRule
	for _, rule := range s.URISamplings {
		if !rule.URIMatcher.MatchString(uri) {
			continue
		}
		result = rule.Rule
		s.uriRuleCache.Add(uri, rule)
	}
	return result
}
