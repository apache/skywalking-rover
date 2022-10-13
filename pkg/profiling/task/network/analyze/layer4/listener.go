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

package layer4

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/sirupsen/logrus"

	"github.com/apache/skywalking-rover/pkg/process/api"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/analyze/base"
	"github.com/apache/skywalking-rover/pkg/profiling/task/network/bpf"
	"github.com/apache/skywalking-rover/pkg/tools"

	v3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"

	"golang.org/x/sys/unix"
)

var Name = "layer4"

type Listener struct {
	// socket retransmit/drop
	socketExceptionStatics       map[SocketBasicKey]*SocketExceptionValue
	socketExceptionOperationLock sync.Mutex
}

func NewListener() *Listener {
	return &Listener{
		socketExceptionStatics: make(map[SocketBasicKey]*SocketExceptionValue),
	}
}

func (l *Listener) Name() string {
	return Name
}

func (l *Listener) GenerateMetrics() base.ListenerMetrics {
	return NewLayer4Metrics()
}

func (l *Listener) RegisterBPFEvents(bpfLoader *bpf.Loader) {
	bpfLoader.ReadEventAsync(bpfLoader.SocketExceptionOperationEventQueue, l.handleSocketExceptionOperationEvent, func() interface{} {
		return &SocketExceptionOperationEvent{}
	})
}

func (l *Listener) ReceiveNewConnection(ctx *base.ConnectionContext, event *base.SocketConnectEvent) {
	// update the connection execute time
	l.getMetrics(ctx.Metrics).ConnectExecuteTime = event.ExeTime
}

func (l *Listener) ReceiveCloseConnection(ctx *base.ConnectionContext, event *base.SocketCloseEvent) {
	layer4 := l.getMetrics(ctx.Metrics)
	// data transmit counters
	layer4.WriteCounter.UpdateToCurrent(event.WriteBytes, event.WriteCount, event.WriteExeTime)
	layer4.ReadCounter.UpdateToCurrent(event.ReadBytes, event.ReadCount, event.ReadExeTime)
	layer4.WriteRTTCounter.UpdateToCurrent(0, event.WriteRTTCount, event.WriteRTTExeTime)

	// connection close execute time
	layer4.CloseExecuteTime = event.ExeTime
}

func (l *Listener) PreFlushConnectionMetrics(ccs []*base.ConnectionWithBPF, bpfLoader *bpf.Loader) error {
	// rebuild to the map for helping quick search correlate ConnectionContext
	keyWithContext := make(map[string]*base.ConnectionContext)
	for _, cc := range ccs {
		// ready to flush histograms
		connection := cc.Connection
		layer4 := l.getMetrics(connection.Metrics)
		// basic counter update
		activeConnection := cc.ActiveInBPF
		if activeConnection != nil {
			layer4.WriteCounter.UpdateToCurrent(activeConnection.WriteBytes, activeConnection.WriteCount, activeConnection.WriteExeTime)
			layer4.ReadCounter.UpdateToCurrent(activeConnection.ReadBytes, activeConnection.ReadCount, activeConnection.ReadExeTime)
			layer4.WriteRTTCounter.UpdateToCurrent(0, activeConnection.WriteRTTCount, activeConnection.WriteRTTExeTime)
		}
		// build cache
		keyWithContext[l.generateConID(connection.ConnectionID, connection.RandomID)] = connection

		if log.Enable(logrus.DebugLevel) {
			log.Debugf("found connection: %d, %s relation: %s:%d(%d) -> %s:%d, protocol: %s, is_ssl: %t, is_closed: %t, write: %d bytes/%d, read: %d bytes/%d",
				connection.ConnectionID, connection.Role.String(),
				connection.LocalIP, connection.LocalPort, connection.LocalPid, connection.RemoteIP, connection.RemotePort,
				connection.Protocol.String(), connection.IsSSL, connection.ConnectionClosed, layer4.WriteCounter.Cur.Bytes,
				layer4.WriteCounter.Cur.Count, layer4.ReadCounter.Cur.Bytes, layer4.ReadCounter.Cur.Count)
		}
	}

	var key HistogramDataKey
	var count uint32
	histogramIt := bpfLoader.SocketConnectionStatsHistogram.Iterate()
	// for-each the stats map
	for histogramIt.Next(&key, &count) {
		// if it's not relate to the ConnectionContext just ignore
		cc := keyWithContext[l.generateConID(key.ConnectionID, key.RandomID)]
		if cc == nil {
			continue
		}
		layer4 := l.getMetrics(cc.Metrics)

		// add the histogram data
		var histogram *SocketDataHistogramWithHistory
		if key.DataDirection == base.SocketDataDirectionEgress {
			if key.DataType == base.SocketDataStaticsTypeExeTime {
				histogram = layer4.WriteExeTimeHistogram
			} else if key.DataType == base.SocketDataStaticsTypeRTT {
				histogram = layer4.WriteRTTHistogram
			}
		} else if key.DataDirection == base.SocketDataDirectionIngress {
			histogram = layer4.ReadExeTimeHistogram
		}
		if histogram == nil {
			log.Warnf("unknown the histogram data: %v", cc)
			continue
		}
		histogram.UpdateToCurrent(key.Bucket, count)

		// delete the stats if the connection already closed
		if cc.ConnectionClosed {
			if err := bpfLoader.SocketConnectionStatsHistogram.Delete(key); err != nil {
				log.Warnf("delete the connection stats failure: %v", err)
			}
		}
	}

	// all the exception operations to the context
	exceptionContexts := l.cleanAndGetAllExceptionContexts()
	l.combineExceptionToConnections(keyWithContext, exceptionContexts)
	return nil
}

func (l *Listener) PostFlushConnectionMetrics(ccs []*base.ConnectionContext) {
	for _, connection := range ccs {
		metrics := l.getMetrics(connection.Metrics)

		// refresh counters
		metrics.WriteCounter.RefreshCurrent()
		metrics.ReadCounter.RefreshCurrent()
		metrics.WriteRTTCounter.RefreshCurrent()
		metrics.WriteRTTHistogram.RefreshCurrent()
		metrics.WriteExeTimeHistogram.RefreshCurrent()
		metrics.ReadExeTimeHistogram.RefreshCurrent()
		metrics.ConnectCounter.RefreshCurrent()
		metrics.CloseCounter.RefreshCurrent()
		metrics.ConnectExeTimeHistogram.RefreshCurrent()
		metrics.CloseExeTimeHistogram.RefreshCurrent()
		metrics.RetransmitCounter.RefreshCurrent()
		metrics.DropCounter.RefreshCurrent()
	}
}

func (l *Listener) FlushMetrics(traffics []*base.ProcessTraffic, builder *base.MetricsBuilder) {
	l.logTheMetricsConnections(traffics)

	metricsPrefix := builder.MetricPrefix()
	for _, traffic := range traffics {
		metrics := traffic.Metrics.GetMetrics(Name).(*Metrics)
		for _, p := range traffic.LocalProcesses {
			collection := make([]*v3.MeterData, 0)
			collection = l.appendCounterValues(collection, metricsPrefix, "write", traffic, p, metrics.WriteCounter)
			collection = l.appendCounterValues(collection, metricsPrefix, "read", traffic, p, metrics.ReadCounter)
			collection = l.appendCounterValues(collection, metricsPrefix, "write_rtt", traffic, p, metrics.WriteRTTCounter)
			collection = l.appendCounterValues(collection, metricsPrefix, "connect", traffic, p, metrics.ConnectCounter)
			collection = l.appendCounterValues(collection, metricsPrefix, "close", traffic, p, metrics.CloseCounter)
			collection = l.appendCounterValues(collection, metricsPrefix, "retransmit", traffic, p, metrics.RetransmitCounter)
			collection = l.appendCounterValues(collection, metricsPrefix, "drop", traffic, p, metrics.DropCounter)

			collection = l.appendHistogramValue(collection, metricsPrefix, "write_rtt", traffic, p, metrics.WriteRTTHistogram)
			collection = l.appendHistogramValue(collection, metricsPrefix, "write_exe_time", traffic, p, metrics.WriteExeTimeHistogram)
			collection = l.appendHistogramValue(collection, metricsPrefix, "read_exe_time", traffic, p, metrics.ReadExeTimeHistogram)
			collection = l.appendHistogramValue(collection, metricsPrefix, "connect_exe_time", traffic, p, metrics.ConnectExeTimeHistogram)
			collection = l.appendHistogramValue(collection, metricsPrefix, "close_exe_time", traffic, p, metrics.CloseExeTimeHistogram)

			if len(collection) == 0 {
				continue
			}

			builder.AppendMetrics(p.Entity().ServiceName, p.Entity().InstanceName, collection)
		}
	}
}

func (l *Listener) logTheMetricsConnections(traffics []*base.ProcessTraffic) {
	if !log.Enable(logrus.DebugLevel) {
		return
	}
	for _, traffic := range traffics {
		side := traffic.Role.String()
		layer4 := l.getMetrics(traffic.Metrics)
		log.Debugf("connection layer4 analyze result: %s : %s, protocol: %s, is SSL: %t, write: %d bytes/%d, read: %d bytes/%d",
			side, traffic.GenerateConnectionInfo(), traffic.Protocol.String(), traffic.IsSSL, layer4.WriteCounter.Cur.Bytes, layer4.WriteCounter.Cur.Count,
			layer4.ReadCounter.Cur.Bytes, layer4.ReadCounter.Cur.Count)
	}
}

func (l *Listener) generateConID(conID, randomID uint64) string {
	return fmt.Sprintf("%d_%d", conID, randomID)
}

func (l *Listener) cleanAndGetAllExceptionContexts() map[SocketBasicKey]*SocketExceptionValue {
	l.socketExceptionOperationLock.Lock()
	defer l.socketExceptionOperationLock.Unlock()

	result := l.socketExceptionStatics
	l.socketExceptionStatics = make(map[SocketBasicKey]*SocketExceptionValue)
	return result
}

func (l *Listener) combineExceptionToConnections(ccs map[string]*base.ConnectionContext, exps map[SocketBasicKey]*SocketExceptionValue) {
	for key, value := range exps {
		var remotePort, localPort = uint16(key.RemotePort), uint16(key.LocalPort)
		var remoteIP, localIP string

		if key.Family == unix.AF_INET {
			remoteIP = parseAddressV4(key.RemoteAddrV4)
			localIP = parseAddressV4(key.LocalAddrV4)
		} else if key.Family == unix.AF_INET6 {
			remoteIP = parseAddressV6(key.RemoteAddrV6)
			localIP = parseAddressV6(key.LocalAddrV6)
		} else {
			continue
		}

		var firstRemoteMatch *base.ConnectionContext
		var foundAllAddrMatch bool
		for _, cc := range ccs {
			// only add to the first matches
			if cc.RemoteIP == remoteIP && cc.RemotePort == remotePort {
				firstRemoteMatch = cc
				if cc.LocalIP == localIP && cc.LocalPort == localPort {
					l.mergeExceptionToAppointConnection(value, cc)
					foundAllAddrMatch = true
					break
				}
			}
		}

		// if only remote address match, then just add to the first one
		if !foundAllAddrMatch && firstRemoteMatch != nil {
			l.mergeExceptionToAppointConnection(value, firstRemoteMatch)
		}
	}
}

func (l *Listener) mergeExceptionToAppointConnection(expCtx *SocketExceptionValue, conCtx *base.ConnectionContext) {
	layer4 := l.getMetrics(conCtx.Metrics)
	layer4.DropCounter.IncreaseToCurrent(NewSocketDataCounterWithValue(0, uint64(expCtx.DropCount), 0))
	layer4.RetransmitCounter.IncreaseToCurrent(NewSocketDataCounterWithValue(0, uint64(expCtx.RetransmitCount), 0))
}

func (l *Listener) appendCounterValues(metrics []*v3.MeterData, metricsPrefix, name string, traffic *base.ProcessTraffic,
	local api.ProcessInterface, counter *SocketDataCounterWithHistory) []*v3.MeterData {
	metric := counter.Cur
	if !metric.NotEmpty() {
		return metrics
	}

	count := float64(metric.Count)
	metrics = append(metrics, l.buildSingleValue(metricsPrefix, name+"_counts_counter", traffic, local, count))
	if metric.Bytes > 0 {
		metrics = append(metrics, l.buildSingleValue(metricsPrefix, name+"_bytes_counter", traffic, local, float64(metric.Bytes)))
	}
	if metric.ExeTime > 0 {
		metrics = append(metrics, l.buildSingleValue(metricsPrefix, name+"_exe_time_counter", traffic, local, float64(metric.ExeTime)/count))
	}
	return metrics
}

func (l *Listener) appendHistogramValue(metrics []*v3.MeterData, metricsPrefix, name string, traffic *base.ProcessTraffic,
	local api.ProcessInterface, histogram *SocketDataHistogramWithHistory) []*v3.MeterData {
	data := histogram.Cur
	if !data.NotEmpty() {
		return metrics
	}

	role, labels := l.buildBasicMeterLabels(traffic, local)
	values := make([]*v3.MeterBucketValue, 0)
	for bucket, count := range data.Buckets {
		var bucketInx = int(bucket)
		if bucketInx >= SocketHistogramBucketsCount {
			bucketInx = SocketHistogramBucketsCount - 1
		}
		var buckets []float64
		if data.Unit == HistogramDataUnitUS {
			buckets = SocketHistogramBucketsUs
		} else {
			buckets = SocketHistogramBucketsNs
		}
		values = append(values, &v3.MeterBucketValue{
			Bucket: buckets[bucketInx],
			Count:  int64(count),
		})
	}

	return append(metrics, &v3.MeterData{
		Metric: &v3.MeterData_Histogram{
			Histogram: &v3.MeterHistogram{
				Name:   fmt.Sprintf("%s%s_%s_histogram", metricsPrefix, role.String(), name),
				Labels: labels,
				Values: values,
			},
		},
	})
}

func (l *Listener) buildSingleValue(prefix, name string, traffic *base.ProcessTraffic, local api.ProcessInterface, val float64) *v3.MeterData {
	role, labels := l.buildBasicMeterLabels(traffic, local)

	return &v3.MeterData{
		Metric: &v3.MeterData_SingleValue{
			SingleValue: &v3.MeterSingleValue{
				Name:   fmt.Sprintf("%s%s_%s", prefix, role.String(), name),
				Labels: labels,
				Value:  val,
			},
		},
	}
}

func (l *Listener) buildBasicMeterLabels(traffic *base.ProcessTraffic, local api.ProcessInterface) (base.ConnectionRole, []*v3.Label) {
	curRole := traffic.Role
	// add the default role
	if curRole == base.ConnectionRoleUnknown {
		curRole = base.ConnectionRoleClient
	}
	labels := make([]*v3.Label, 0)

	// two pair process/address info
	labels = l.appendMeterValue(labels, fmt.Sprintf("%s_process_id", curRole.String()), local.ID())
	labels = l.appendRemoteAddressInfo(labels, traffic, curRole.Revert().String(), local)

	labels = l.appendMeterValue(labels, "side", curRole.String())

	// protocol and ssl
	labels = l.appendMeterValue(labels, "protocol", traffic.Protocol.String())
	labels = l.appendMeterValue(labels, "is_ssl", fmt.Sprintf("%t", traffic.IsSSL))
	return curRole, labels
}

func (l *Listener) appendRemoteAddressInfo(labels []*v3.Label, traffic *base.ProcessTraffic, prefix string, local api.ProcessInterface) []*v3.Label {
	if len(traffic.RemoteProcesses) != 0 {
		for _, p := range traffic.RemoteProcesses {
			// only match with same service instance
			if local.Entity().ServiceName == p.Entity().ServiceName &&
				local.Entity().InstanceName == p.Entity().InstanceName {
				return l.appendMeterValue(labels, prefix+"_process_id", p.ID())
			}
		}
	}

	if tools.IsLocalHostAddress(traffic.RemoteIP) || traffic.Analyzer.IsLocalAddressInCache(traffic.RemoteIP) {
		return l.appendMeterValue(labels, prefix+"_local", "true")
	}

	return l.appendMeterValue(labels, prefix+"_address", fmt.Sprintf("%s:%d", traffic.RemoteIP, traffic.RemotePort))
}

func (l *Listener) appendMeterValue(labels []*v3.Label, name, value string) []*v3.Label {
	return append(labels, &v3.Label{
		Name:  name,
		Value: value,
	})
}

func (l *Listener) getMetrics(connectionMetrics *base.ConnectionMetrics) *Metrics {
	return connectionMetrics.GetMetrics(Name).(*Metrics)
}

type HistogramDataKey struct {
	ConnectionID  uint64
	RandomID      uint64
	DataDirection base.SocketDataDirection
	DataType      base.SocketDataStaticsType
	Bucket        uint64
}

func parseAddressV4(val uint32) string {
	return net.IP((*(*[net.IPv4len]byte)(unsafe.Pointer(&val)))[:]).String()
}

func parseAddressV6(val [16]uint8) string {
	return net.IP((*(*[net.IPv6len]byte)(unsafe.Pointer(&val)))[:]).String()
}
