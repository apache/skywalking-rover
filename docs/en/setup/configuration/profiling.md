# Profiling Module

The profiling module is used to profiling the processes from the [Process Discovery Module](../process_discovery/overview.md),
and send the snapshot to the backend server.

## Configuration

| Name                                                                            | Default     | Environment Key                                                                       | Description                                                                           |
|---------------------------------------------------------------------------------|-------------|---------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| profiling.active                                                                | true        | ROVER_PROFILING_ACTIVE                                                                | Is active the process profiling.                                                      |
| profiling.check_interval                                                        | 10s         | ROVER_PROFILING_CHECK_INTERVAL                                                        | Check the profiling task interval.                                                    |
| profiling.flush_interval                                                        | 5s          | ROVER_PROFILING_FLUSH_INTERVAL                                                        | Combine existing profiling data and report to the backend interval.                   |
| profiling.task.on_cpu.dump_period                                               | 9ms         | ROVER_PROFILING_TASK_ON_CPU_DUMP_PERIOD                                               | The profiling stack dump period.                                                      |
| profiling.task.network.report_interval                                          | 2s          | ROVER_PROFILING_TASK_NETWORK_TOPOLOGY_REPORT_INTERVAL                                 | The interval of send metrics to the backend.                                          |
| profiling.task.network.meter_prefix                                             | rover_net_p | ROVER_PROFILING_TASK_NETWORK_TOPOLOGY_METER_PREFIX                                    | The prefix of network profiling metrics name.                                         |
| profiling.task.network.protocol_analyze.per_cpu_buffer                          | 400KB       | ROVER_PROFILING_TASK_NETWORK_PROTOCOL_ANALYZE_PER_CPU_BUFFER                          | The size of socket data buffer on each CPU.                                           |
| profiling.task.network.protocol_analyze.parallels                               | 2           | ROVER_PROFILING_TASK_NETWORK_PROTOCOL_ANALYZE_PARALLELS                               | The count of parallel protocol analyzer.                                              |
| profiling.task.network.protocol_analyze.queue_size                              | 5000        | ROVER_PROFILING_TASK_NETWORK_PROTOCOL_ANALYZE_QUEUE_SIZE                              | The size of per paralleled analyzer queue.                                            |
| profiling.task.network.protocol_analyze.sampling.http.default_request_encoding  | UTF-8       | ROVER_PROFILING_TASK_NETWORK_PROTOCOL_ANALYZE_SAMPLING_HTTP_DEFAULT_REQUEST_ENCODING  | The default body encoding when sampling the request.                                  |
| profiling.task.network.protocol_analyze.sampling.http.default_response_encoding | UTF-8       | ROVER_PROFILING_TASK_NETWORK_PROTOCOL_ANALYZE_SAMPLING_HTTP_DEFAULT_RESPONSE_ENCODING | The default body encoding when sampling the response.                                 |
| profiling.continuous.meter_prefix                                               | rover_con_p | ROVER_PROFILING_CONTINUOUS_METER_PREFIX                                               | The continuous related meters prefix name.                                            |
| profiling.continuous.fetch_interval                                             | 1s          | ROVER_PROFILING_CONTINUOUS_FETCH_INTERVAL                                             | The interval of fetch metrics from the system, such as Process CPU, System Load, etc. |
| profiling.continuous.check_interval                                             | 5s          | ROVER_PROFILING_CONTINUOUS_CHECK_INTERVAL                                             | The interval of check metrics is reach the thresholds.                                |
| profiling.continuous.trigger.execute_duration                                   | 10m         | ROVER_PROFILING_CONTINUOUS_TRIGGER_EXECUTE_DURATION                                   | The duration of the profiling task.                                                   |
| profiling.continuous.trigger.silence_duration                                   | 20m         | ROVER_PROFILING_CONTINUOUS_TRIGGER_SILENCE_DURATION                                   | The minimal duration between the execution of the same profiling task.                |

## Prepare service

Before profiling your service, please make sure your service already has the symbol data inside the binary file.
So we could locate the stack symbol, It could be checked following these ways:
1. **objdump**: Using `objdump --syms path/to/service`.
2. **readelf**: Using `readelf --syms path/to/service`.

## Profiling Type

All the profiling tasks are using the [Linux Official Function](https://man7.org/linux/man-pages/man2/perf_event_open.2.html) and `kprobe` or `uprobe` to open perf event,
and attach the eBPF Program to dump stacks.

### On CPU

On CPU Profiling task is using `PERF_COUNT_SW_CPU_CLOCK` to profiling the process with the CPU clock.

### Off CPU

Off CPU Profiling task is attach the `finish_task_switch` in `krobe` to profiling the process.

### Network

Network Profiling task is intercept IO-related syscall and `urprobe` in process to identify the network traffic and generate the metrics.
Also, the following protocol are supported for analyzing using OpenSSL library, BoringSSL library, GoTLS, NodeTLS or plaintext:

1. HTTP/1.x
2. HTTP/2
3. MySQL
4. CQL(The Cassandra Query Language)
5. MongoDB
6. Kafka
7. DNS

#### Collecting data

Network profiling uses metrics, logs send to the backend service.

##### Data Type

The network profiling has customized the following two types of metrics to represent the network data:
1. **Counter**: Records the total number of data in a certain period of time. Each counter containers the following data:
   1. **Count**: The count of the execution.
   2. **Bytes**: The package size of the execution.
   3. **Exe Time**: The consumed time(nanosecond) of the execution. 
2. **Histogram**: Records the distribution of the data in the bucket.
3. **TopN**: Record the highest latency data in a certain period of time.

##### Labels

Each metric contains the following labels to identify the process relationship:

| Name                                     | Type    | Description                                                                                                                  |
|------------------------------------------|---------|------------------------------------------------------------------------------------------------------------------------------|
| client_process_id or server_process_id   | string  | The ID of the current process, which is determined by the role of the current process in the connection as server or client. |
| client_local or server_local             | boolean | The remote process is a local process.                                                                                       |
| client_address or server_address         | string  | The remote process address. ex: `IP:port`.                                                                                   |
| side                                     | enum    | The current process is either "client" or "server" in this connection.                                                       |
| protocol                                 | string  | Identification the protocol based on the package data content.                                                               |
| is_ssl                                   | bool    | Is the current connection using SSL.                                                                                         |

##### Layer-4 Data

Based on the above two data types, the following metrics are provided. 

| Name                  | Type      | Unit         | Description                                                               |
|-----------------------|-----------|--------------|---------------------------------------------------------------------------|
| write                 | Counter   | nanosecond   | The socket write counter                                                  |
| read                  | Counter   | nanosecond   | The socket read counter                                                   |
| write RTT             | Counter   | microsecond  | The socket write RTT counter                                              |
| connect               | Counter   | nanosecond   | The socket connect/accept with other server/client counter                |
| close                 | Counter   | nanosecond   | The socket close counter                                                  |
| retransmit            | Counter   | nanosecond   | The socket retransmit package counter                                     |
| drop                  | Counter   | nanosecond   | The socket drop package counter                                           |
| write RTT             | Histogram | microsecond  | The socket write RTT execute time histogram                               |
| write execute time    | Histogram | nanosecond   | The socket write data execute time histogram                              |
| read execute time     | Histogram | nanosecond   | The socket read data execute time histogram                               |
| connect execute time  | Histogram | nanosecond   | The socket connect/accept with other server/client execute time histogram |
| close execute time    | Histogram | nanosecond   | The socket close execute time histogram                                   |

##### HTTP/1.x Data

##### Metrics

| Name                        | Type      | Unit        | Description                                             |
|-----------------------------|-----------|-------------|---------------------------------------------------------|
| http1_request_cpm           | Counter   | count       | The HTTP request counter                                |
| http1_response_status_cpm   | Counter   | count       | The count of per HTTP response code                     |
| http1_request_package_size  | Histogram | Byte size   | The request package size                                |
| http1_response_package_size | Histogram | Byte size   | The response package size                               |
| http1_client_duration       | Histogram | millisecond | The duration of single HTTP response on the client side |
| http1_server_duration       | Histogram | millisecond | The duration of single HTTP response on the server side |

##### Logs 

| Name        | Type  | Unit        | Description                                          |
|-------------|-------|-------------|------------------------------------------------------|
| slow_traces | TopN  | millisecond | The Top N slow trace(id)s                            |
| status_4xx  | TopN  | millisecond | The Top N trace(id)s with response status in 400-499 |
| status_5xx  | TopN  | millisecond | The Top N trace(id)s with response status in 500-599 |

##### Span Attached Event
| Name                   | Description                                                                                                                                 |
|------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| HTTP Request Sampling  | Complete information about the HTTP request, it's only reported when it matches slow/4xx/5xx traces.                                        |
| HTTP Response Sampling | Complete information about the HTTP response, it's only reported when it matches slow/4xx/5xx traces.                                       |
| Syscall xxx            | The methods to use when the process invoke with the network-related syscall method. It's only reported when it matches slow/4xx/5xx traces. |

## Continuous Profiling

The continuous profiling feature monitors low-power target process information, including process CPU usage and network requests, based on configuration passed from the backend. 
When a threshold is met, it automatically initiates a profiling task(on/off CPU, Network) to provide more detailed analysis.

### Monitor Type

#### System Load

Monitor the average system load for the last minute, which is equivalent to using the first value of the `load average` in the `uptime` command.

#### Process CPU

The target process utilizes a certain percentage of the CPU on the current host.

#### Process Thread Count

The real-time number of threads in the target process.

#### Network

Network monitoring uses eBPF technology to collect real-time performance data of the current process responding to requests. Requests sent upstream are not monitored by the system.

Currently, network monitoring supports parsing of the HTTP/1.x protocol and supports the following types of monitoring:

1. `Error Rate`: The percentage of network request errors, such as HTTP status codes within the range of `[500-600)`, is considered as erroneous.
2. `Avg Response Time`: Average response time(ms) for specified URI.

### Metrics

Rover would periodically send collected monitoring data to the backend using the `Native Meter Protocol`.

| Name                   | Unit     | Description                                                               |
|------------------------|----------|---------------------------------------------------------------------------|
| process_cpu            | (0-100)% | The CPU usage percent                                                     |
| process_thread_count   | count    | The thread count of process                                               |
| system_load            | count    | The average system load for the last minute, each process have same value |
| http_error_rate        | (0-100)% | The network request error rate percentage                                 |
| http_avg_response_time | ms       | The network average response duration                                     |