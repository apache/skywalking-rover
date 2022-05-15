# Process Discovery Module

The process Discovery module is used to discover the existing processes in the current machine and report them to the backend service.
After the process upload is completed, the other modules could perform more operations with the process, such as process profiling and collecting process metrics.

## Configuration

| Name | Default | Environment Key | Description |
|------|---------|-----------------|-------------|
| process_discovery.heartbeat_period | 20s | ROVER_PROCESS_DISCOVERY_HEARTBEAT_PERIOD | The period of report or keep-alive process to the backend. |
| process_discovery.properties_report_period | 10 | ROVER_PROCESS_DISCOVERY_PROPERTIES_REPORT_PERIOD | The agent sends the process properties to the backend every: heartbeart period * properties report period. |

## Process Detector

Process Detector is used to detect the process from the VM with the different environments:
1. [Linux Process Scanner](./scanner.md)
2. [Kubernetes Process Detector](./kubernetes.md)
