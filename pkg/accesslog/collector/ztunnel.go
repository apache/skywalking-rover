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

package collector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/cache"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
	"github.com/apache/skywalking-rover/pkg/accesslog/events"
	"github.com/apache/skywalking-rover/pkg/module"
	"github.com/apache/skywalking-rover/pkg/tools/elf"
	"github.com/apache/skywalking-rover/pkg/tools/host"

	v3 "skywalking.apache.org/repo/goapi/collect/ebpf/accesslog/v3"

	"github.com/shirou/gopsutil/process"
)

var (
	// ZTunnelProcessFinderInterval is the interval to find ztunnel process
	ZTunnelProcessFinderInterval = time.Second * 30
	// ZTunnelTrackBoundSymbolPrefix is the prefix of the symbol name to track outbound connections in ztunnel process
	// ztunnel::proxy::connection_manager::ConnectionManager::track_outbound
	ZTunnelTrackBoundSymbolPrefix = "_ZN7ztunnel5proxy18connection_manager17ConnectionManager14track_outbound"
)

var zTunnelCollectInstance = NewZTunnelCollector(time.Minute)

// ZTunnelCollector is a collector for ztunnel process in the Ambient Istio scenario
type ZTunnelCollector struct {
	ctx    context.Context
	cancel context.CancelFunc
	alc    *common.AccessLogContext

	collectingProcess       *process.Process
	ipMappingCache          *cache.Expiring
	ipMappingExpireDuration time.Duration
}

func NewZTunnelCollector(expireTime time.Duration) *ZTunnelCollector {
	return &ZTunnelCollector{
		ipMappingCache:          cache.NewExpiring(),
		ipMappingExpireDuration: expireTime,
	}
}

func (z *ZTunnelCollector) Start(mgr *module.Manager, ctx *common.AccessLogContext) error {
	z.ctx, z.cancel = context.WithCancel(ctx.RuntimeContext)
	z.alc = ctx
	ctx.ConnectionMgr.RegisterNewFlushListener(z)

	err := z.findZTunnelProcessAndCollect()
	if err != nil {
		return err
	}

	ctx.BPF.ReadEventAsync(ctx.BPF.ZtunnelLbSocketMappingEventQueue, func(data interface{}) {
		event := data.(*events.ZTunnelSocketMappingEvent)
		localIP := z.convertBPFIPToString(event.OriginalSrcIP)
		localPort := event.OriginalSrcPort
		remoteIP := z.convertBPFIPToString(event.OriginalDestIP)
		remotePort := event.OriginalDestPort
		lbIP := z.convertBPFIPToString(event.LoadBalancedDestIP)
		log.Debugf("received ztunnel lb socket mapping event: %s:%d -> %s:%d, lb: %s", localIP, localPort, remoteIP, remotePort, lbIP)

		key := z.buildIPMappingCacheKey(localIP, int(localPort), remoteIP, int(remotePort))
		z.ipMappingCache.Set(key, &ZTunnelLoadBalanceAddress{
			IP:   lbIP,
			Port: event.LoadBalancedDestPort,
		}, z.ipMappingExpireDuration)
	}, func() interface{} {
		return &events.ZTunnelSocketMappingEvent{}
	})
	go func() {
		ticker := time.NewTicker(ZTunnelProcessFinderInterval)
		for {
			select {
			case <-ticker.C:
				err := z.findZTunnelProcessAndCollect()
				if err != nil {
					log.Error("failed to find and collect ztunnel process: ", err)
				}
			case <-z.ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
	return nil
}

func (z *ZTunnelCollector) ReadyToFlushConnection(connection *common.ConnectionInfo, _ events.Event) {
	if connection == nil || connection.Socket == nil || connection.RPCConnection == nil || connection.RPCConnection.Attachment != nil {
		return
	}
	key := z.buildIPMappingCacheKey(connection.Socket.SrcIP, int(connection.Socket.SrcPort),
		connection.Socket.DestIP, int(connection.Socket.DestPort))
	lbIPObj, found := z.ipMappingCache.Get(key)
	if !found {
		log.Debugf("there no ztunnel mapped IP address found for connection ID: %d, random ID: %d",
			connection.ConnectionID, connection.RandomID)
		return
	}
	address := lbIPObj.(*ZTunnelLoadBalanceAddress)
	log.Debugf("found the ztunnel load balanced IP for the connection: %s, connectionID: %d, randomID: %d", address,
		connection.ConnectionID, connection.RandomID)
	securityPolicy := v3.ZTunnelAttachmentSecurityPolicy_NONE
	// if the target port is 15008, this mean ztunnel have use mTLS
	if address.Port == 15008 {
		securityPolicy = v3.ZTunnelAttachmentSecurityPolicy_MTLS
	}
	connection.RPCConnection.Attachment = &v3.ConnectionAttachment{
		Environment: &v3.ConnectionAttachment_ZTunnel{
			ZTunnel: &v3.ZTunnelAttachmentEnvironment{
				RealDestinationIp: address.IP,
				By:                v3.ZTunnelAttachmentEnvironmentDetectBy_ZTUNNEL_OUTBOUND_FUNC,
				SecurityPolicy:    securityPolicy,
			},
		},
	}
}

func (z *ZTunnelCollector) convertBPFIPToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, ip>>16&0xff, ip>>8&0xff, ip&0xff)
}

func (z *ZTunnelCollector) buildIPMappingCacheKey(localIP string, localPort int, remoteIP string, remotePort int) string {
	return fmt.Sprintf("%s:%d-%s:%d", localIP, localPort, remoteIP, remotePort)
}

func (z *ZTunnelCollector) Stop() {
	if z.cancel != nil {
		z.cancel()
	}
}

func (z *ZTunnelCollector) findZTunnelProcessAndCollect() error {
	if z.collectingProcess != nil {
		running, err := z.collectingProcess.IsRunning()
		if err == nil && running {
			// already collecting the process
			return nil
		}
		log.Warnf("detected ztunnel process is not running, should re-scan process to find and collect it")
	}

	processes, err := process.Processes()
	if err != nil {
		return err
	}
	var zTunnelProcess *process.Process
	for _, p := range processes {
		name, err := p.Exe()
		if err != nil {
			continue
		}
		if strings.HasSuffix(name, "/ztunnel") {
			zTunnelProcess = p
			break
		}
	}

	if zTunnelProcess == nil {
		log.Debugf("ztunnel process not found is current node")
		return nil
	}

	log.Infof("ztunnel process founded in current node, pid: %d", zTunnelProcess.Pid)
	z.collectingProcess = zTunnelProcess
	return z.collectZTunnelProcess(zTunnelProcess)
}

func (z *ZTunnelCollector) collectZTunnelProcess(p *process.Process) error {
	pidExeFile := host.GetHostProcInHost(fmt.Sprintf("%d/exe", p.Pid))
	elfFile, err := elf.NewFile(pidExeFile)
	if err != nil {
		return fmt.Errorf("read executable file error: %v", err)
	}
	trackBoundSymbol := elfFile.FilterSymbol(func(name string) bool {
		return strings.HasPrefix(name, ZTunnelTrackBoundSymbolPrefix)
	}, true)
	if len(trackBoundSymbol) == 0 {
		return fmt.Errorf("failed to find track outbound symbol in ztunnel process")
	}

	uprobeFile := z.alc.BPF.OpenUProbeExeFile(pidExeFile)
	uprobeFile.AddLink(trackBoundSymbol[0].Name, z.alc.BPF.ConnectionManagerTrackOutbound, nil)
	return nil
}

type ZTunnelLoadBalanceAddress struct {
	IP   string
	Port uint16
}
