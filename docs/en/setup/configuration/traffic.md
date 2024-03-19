# Traffic

The traffic is used to collecting the network access logs from services through the [Service Discovery](service-discovery.md),
and send [access logs](https://github.com/apache/skywalking-data-collect-protocol/blob/master/ebpf/accesslog.proto) to the backend server for analyze.

## Configuration

| Name                                       | Default                               | Environment Key                                  | Description                                                                                                    |
|--------------------------------------------|---------------------------------------|--------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| access_log.active                          | false                                 | ROVER_ACCESS_LOG_ACTIVE                          | Is active the access log monitoring.                                                                           |
| access_log.exclude_namespaces              | istio-system,cert-manager,kube-system | ROVER_ACCESS_LOG_EXCLUDE_NAMESPACES              | Exclude processes in the specified Kubernetes namespace. Multiple namespaces split by ","                      |
| access_log.exclude_cluster                 |                                       | ROVER_ACCESS_LOG_EXCLUDE_CLUSTER                 | Exclude processes in the specified cluster which defined in the process module. Multiple clusters split by "," |
| access_log.flush.max_count                 | 2000                                  | ROVER_ACCESS_LOG_FLUSH_MAX_COUNT                 | The max count of the access log when flush to the backend.                                                     |
| access_log.flush.period                    | 5s                                    | ROVER_ACCESS_LOG_FLUSH_PERIOD                    | The period of flush access log to the backend.                                                                 |
| access_log_protocol_analyze.per_cpu_buffer | 400KB                                 | ROVER_ACCESS_LOG_PROTOCOL_ANALYZE_PER_CPU_BUFFER | The size of socket data buffer on each CPU.                                                                    |
| access_log.protocol_analyze.parallels      | 2                                     | ROVER_ACCESS_LOG_PROTOCOL_ANALYZE_PARALLELS      | The count of parallel protocol analyzer.                                                                       |
| access_log.protocol_analyze.queue_size     | 5000                                  | ROVER_ACCESS_LOG_PROTOCOL_ANALYZE_QUEUE_SIZE     | The size of per paralleled analyze queue.                                                                      |


## Collectors

### Socket Connect/Accept/Close

Monitor all socket `connect`, `accept`, and `close` events from monitored processes by attaching eBPF program to the respective [trace points](https://docs.kernel.org/trace/tracepoints.html).

### Socket traffic

Capture all socket traffic from monitored processes by attaching eBPF program to [network syscalls](https://linasm.sourceforge.net/docs/syscalls/network.php). 

#### Protocol

Data collection is followed by protocol analysis. Currently, the supported protocols include:

1. HTTP/1.x
2. HTTP/2

Note: As HTTP2 is a stateful protocol, it only supports monitoring processes that start after monitor. Processes already running at the time of monitoring may fail to provide complete data, leading to unsuccessful analysis.

#### TLS

When a process uses the TLS protocol for data transfer, Rover monitors libraries such as OpenSSL, BoringSSL, GoTLS, and NodeTLS to access the raw content. 
This feature is also applicable for protocol analysis. 

Note: the parsing of TLS protocols in Java is currently not supported.

#### L2-L4

During data transmission, Rover records each packet's through the network layers L2 to L4 using [kprobes](https://docs.kernel.org/trace/kprobes.html). 
This approach enhances the understanding of each packet's transmission process, facilitating easier localization and troubleshooting of network issues.
