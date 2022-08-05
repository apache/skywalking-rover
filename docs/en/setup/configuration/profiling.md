# Profiling Module

The profiling module is used to profiling the processes from the [Process Discovery Module](../process_discovery/overview.md),
and send the snapshot to the backend server.

## Configuration

| Name | Default | Environment Key | Description |
|------|---------|-----------------|-------------|
| profiling.active | true | ROVER_PROFILING_ACTIVE | Is active the process profiling. |
| profiling.check_interval | 10s | ROVER_PROFILING_CHECK_INTERVAL | Check the profiling task interval. |
| profiling.flush_interval | 5s | Combine existing profiling data and report to the backend interval. |
| task.on_cpu.dump_period | 9ms | The on CPU profiling thread stack dump period. |
| task.network.report_interval | 2s | The interval of send network profiling metrics to the backend. |
| task.network.meter_prefix | rover_net_p | The prefix of network profiling metrics name. |

## Profiling Type

All the profiling tasks are using the [Linux Official Function](https://man7.org/linux/man-pages/man2/perf_event_open.2.html) and `kprobe` or `uprobe` to open perf event,
and attach the eBPF Program to dump stacks.

### On CPU

On CPU Profiling task is using `PERF_COUNT_SW_CPU_CLOCK` to profiling the process with the CPU clock.

### Off CPU

Off CPU Profiling task is attach the `finish_task_switch` in `krobe` to profiling the process.

### Network

Network Profiling task is intercept IO-related syscall and `urprobe` in process to identify the network traffic and generate the metrics.
Also, the following protocol are supported for analyzing using OpenSSL library, BoringSSL library or plaintext:

1. HTTP
2. MySQL
3. CQL(The Cassandra Query Language)
4. MongoDB
5. Kafka
6. DNS

## Configuration

| Name | Default | Environment Key | Description |
|------|---------|-----------------|-------------|
| profiling.task.on_cpu.dump_period | 9ms | ROVER_PROFILING_TASK_ON_CPU_DUMP_PERIOD | The profiling stack dump period. |
