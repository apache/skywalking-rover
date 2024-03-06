# Setup

The first and most important thing is, that SkyWalking Rover startup behaviors are driven by configs/rover_configs.yaml. Understanding the setting file will help you to read this document.

## Requirements and default settings

Before you start, you should know that the main purpose of quickstart is to help you obtain a basic configuration for previews/demos.
Usually, the process to be monitored is first declared.

Then, you can use `bin/startup.sh` to start up the rover with their [config](../../../configs/rover_configs.yaml).

### SkyWalking OAP

The SkyWalking Rover requires specialized protocols to communicate with SkyWalking OAP.

| SkyWalking Rover Version | SkyWalking OAP | Notice                   |
|--------------------------|----------------|--------------------------|
| 0.6.0+                   | \> = 10.0.0    | Only support Kubernetes. | 
| 0.1.0+                   | \> = 9.1.0     |                          |


## Startup script
Startup Script
```shell script
bin/startup.sh 
```

## Examples

You can quickly build your Rover according to the following examples:

### Deploy

1. [Deploy on Kubernetes](examples/deploy/kubernetes/readme.md)

### Use Cases

1. [Profiling a Golang/C/C++/Rust service on Linux](examples/cases/profiling-process/readme.md)
1. [Detect Process by Agent Sensor](examples/cases/agent-sensor/readme.md)
1. [Detect Process in Kubernetes Environemnt](examples/cases/kubernetes-process/readme.md)

## Configuration

The core concept behind this setting file is, that SkyWalking Rover is based on pure modularization design. The end-user can switch or assemble the collector features to their requirements.

So, in rover_configs.yaml, there contains these parts.
1. [Logger Module](./configuration/logger.md).
2. [Core Module](./configuration/core.md).
3. [Process Discovery Module](configuration/process-discovery.md).
4. [Profiling Module](./configuration/profiling.md).
5. [Access Log Module](./configuration/accesslog.md).

Also, You could using [Overriding Setting](./configuration/override-settings.md) feature to setup the configuration.

## Prerequisites

Currently, Linux operating systems are supported from version `4.9` and above, except for network profiling which requires version `4.16` or higher. 

The following table are currently support operating systems.

| System           | Kernel Version | On CPU Profiling | Off CPU Profiling | Network Profiling              |
|------------------|----------------|------------------|-------------------|--------------------------------|
| CentOS 7         | 3.10.0         | No               | No                | No                             |
| CentOS Stream 8  | 4.18.0         | Yes              | Yes               | Yes                            |
| CentOS Stream 9  | 5.47.0         | Yes              | Yes               | Yes                            |
| Debian 10        | 4.19.0         | Yes              | Yes               | Yes                            |
| Debian 11        | 5.10.0         | Yes              | Yes               | Yes(TCP Drop Monitor Excluded) |
| Fedora 35        | 5.14.10        | Yes              | Yes               | Yes(TCP Drop Monitor Excluded) |
| RHEL 7           | 3.10.0         | No               | No                | No                             |
| RHEL 8           | 4.18.0         | Yes              | Yes               | Yes                            |
| RHEL 9           | 5.14.0         | Yes              | Yes               | Yes                            |
| Rocky Linux 8    | 4.18.0         | Yes              | Yes               | Yes                            |
| Rocky Linux 9    | 5.14.0         | Yes              | Yes               | Yes                            |
| Ubuntu 1804      | 5.4.0          | Yes              | Yes               | Yes                            |
| Ubuntu 20.04     | 5.15.0         | Yes              | Yes               | Yes                            |
| Ubuntu 20.04     | 5.15.0         | Yes              | Yes               | Yes                            |
| Ubuntu 22.04     | 5.15.0         | Yes              | Yes               | Yes                            |
| Ubuntu 22.04     | 5.15.0         | Yes              | Yes               | Yes                            |
| Ubuntu 22.10     | 5.19.0         | Yes              | Yes               | Yes                            |
| Ubuntu Pro 16.04 | 4.15.0         | Yes              | Yes               | No                             |
| Ubuntu Pro 18.04 | 5.4.0          | Yes              | Yes               | Yes                            |
| Ubuntu Pro 20.04 | 5.15.0         | Yes              | Yes               | Yes                            |
| Ubuntu Pro 22.04 | 5.15.0         | Yes              | Yes               | Yes                            |
| Ubuntu Pro 22.04 | 5.15.0         | Yes              | Yes               | Yes                            |

