# Module Design
## Overview

The module is an isolation concept in Rover. Each module completes an independent feature.

## Life Cycle

Each concept has a complete life cycle.

- Start: Start phase is to start the current module.
- NotifyStartSuccess: Execute when all modules have finished starting without any errors.
- Shutdown: The shutdown phase is to close all the used resources.

## Config

Each module has its corresponding configurations and only when they're set in the configuration file, the module would be enabled.

The config data support various data structures, and it could use `${ENV_NAME:DEFAULT}` to read the value from the environment variables.

## Dependency

There may have dependencies between modules.

For example, process and profiling are two separate modules, the profiling module needs to read all registered processes from the processing module. So, we could say the profiling module is dependent on the process module.

### Module API

Modules can communicate by calling APIs from dependent modules.

### Start Sequence

When Rover starts, it would analyze the dependency order of all enabled modules to a startup module list.

The startup sequence is following these steps:
1. Modules have the fewest dependent modules.
2. The position of the module declaration in the configuration file.

After parsing the list of startup modules, it would be started sequentially in a single-threaded manner.