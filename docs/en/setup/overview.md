# Setup

The first and most important thing is, that SkyWalking Rover startup behaviors are driven by configs/rover_configs.yaml. Understanding the setting file will help you to read this document.

## Requirements and default settings

Before you start, you should know that the main purpose of quickstart is to help you obtain a basic configuration for previews/demos.
Usually, the process to be monitored is first declared.

Then, you can use `bin/startup.sh` to start up the rover with their config[../../../configs/rover_configs.yaml].

## Startup script
Startup Script
```shell script
bin/startup.sh 
```

## Examples

You can quickly build your Rover according to the following examples:

### Deploy

1. [Deploy on Linux](examples/deploy/linux/readme.md)

### Use Cases

1. [Profiling a Golang/C service on Linux](examples/cases/profiling-process/readme.md)

## Configuration

The core concept behind this setting file is, that SkyWalking Rover is based on pure modularization design. The end-user can switch or assemble the collector features to their requirements.

So, in rover_configs.yaml, there contains these parts.
1. [Core Module](./configuration/core.md).
2. [Process Discovery Module](./configuration/process_discovery/overview.md).
3. [Profiling Module](./configuration/profiling.md).

Also, You could using [Overriding Setting](./configuration/override-settings.md) feature to setup the configuration.