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

// Package telemetry exposes what the agent knows about itself.
//
// The questions it exists to answer are operational: how many socket data events are waiting to be
// analyzed and how much memory do they hold, how long ago did a partition last run, how far behind
// is the sender. Those are the numbers that decide whether the agent is healthy under load, and
// until they are readable from outside the process they can only be guessed at from a heap profile.
//
// The registry is deliberately dependency free: the values are read from the counters the agent
// already keeps and are written in the Prometheus text format, which any scraper understands.
package telemetry

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Kind string

const (
	// Counter only ever grows, Gauge may go up and down
	Counter Kind = "counter"
	Gauge   Kind = "gauge"
)

// Sample is one value of a metric, with the labels that identify it among the others of that metric
type Sample struct {
	Labels map[string]string
	Value  float64
}

type metric struct {
	name string
	help string
	kind Kind
	read func() []Sample
}

var (
	registryLocker sync.RWMutex
	registry       []metric
)

// Register adds a metric with a single value. The function is called when the metrics are read, so
// it must be cheap and must not block: it runs while the agent is serving its data path.
func Register(name, help string, kind Kind, read func() float64) {
	RegisterSeries(name, help, kind, func() []Sample { return []Sample{{Value: read()}} })
}

// RegisterSeries adds a metric that reports several labelled values, for example one per partition
func RegisterSeries(name, help string, kind Kind, read func() []Sample) {
	registryLocker.Lock()
	defer registryLocker.Unlock()
	for i := range registry {
		if registry[i].name == name {
			// a re-registration replaces the reader: the second one belongs to the live object
			registry[i] = metric{name: name, help: help, kind: kind, read: read}
			return
		}
	}
	registry = append(registry, metric{name: name, help: help, kind: kind, read: read})
}

// Write renders every registered metric in the Prometheus text exposition format
func Write(w io.Writer) error {
	registryLocker.RLock()
	snapshot := make([]metric, len(registry))
	copy(snapshot, registry)
	registryLocker.RUnlock()

	sort.Slice(snapshot, func(i, j int) bool { return snapshot[i].name < snapshot[j].name })
	for _, m := range snapshot {
		samples := m.read()
		if len(samples) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", m.name, m.help, m.name, m.kind); err != nil {
			return err
		}
		for _, s := range samples {
			if _, err := fmt.Fprintf(w, "%s%s %s\n", m.name, formatLabels(s.Labels), formatValue(s.Value)); err != nil {
				return err
			}
		}
	}
	return nil
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		// the value is escaped here, so it is quoted directly rather than with %q, which would escape twice
		pairs = append(pairs, fmt.Sprintf("%s=\"%s\"", name, escapeLabelValue(labels[name])))
	}
	return "{" + strings.Join(pairs, ",") + "}"
}

func escapeLabelValue(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(value)
}

func formatValue(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}
