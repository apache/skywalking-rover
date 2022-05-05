# Profiling Module

The profiling module is used to profiling the processes from the [Process Discovery Module](../process_discovery/overview.md),
and send the snapshot to the backend server.

## Configuration

| Name | Default | Environment Key | Description |
|------|---------|-----------------|-------------|
| profiling.active | true | ROVER_PROFILING_ACTIVE | Is active the process profiling. |
| profiling.check_interval | 10s | ROVER_PROFILING_CHECK_INTERVAL | Check the profiling task interval. |
| profiling.flush_interval | 5s | Combine existing profiling data and report to the backend interval |

## Profiling Type

All the profiling tasks are using the [Linux Official Function](https://man7.org/linux/man-pages/man2/perf_event_open.2.html) to open perf event,
and attach the eBPF Program to dump stacks.

### On CPU

On CPU Profiling task is using `PERF_COUNT_SW_CPU_CLOCK` to profiling the process with the CPU clock.

## Configuration

| Name | Default | Environment Key | Description |
|------|---------|-----------------|-------------|
| profiling.task.on_cpu.dump_period | 9ms | ROVER_PROFILING_TASK_ON_CPU_DUMP_PERIOD | The profiling stack dump period. |
