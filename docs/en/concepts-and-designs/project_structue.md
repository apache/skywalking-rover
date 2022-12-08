# Project Structure
- cmd: The starter of Rover.
- configs: Rover configs.
- bpf: All the BPF programs with C code.
- docker: Docker files for build Rover image.
- docs: The documentation of Rover.
- pkg: Contains all modules and basic framework.
    - logger: Manage the log.
    - config: Read config for start.
    - module: The interface of each module.
    - boot: Manage all enabled module life cycle.
    - core: Manage the connection with OAP.
    - process: Manage the process detect and upload them to the OAP.
    - profiling: Manage the profiling tasks and upload data to the OAP.
    - tools: Sharing tools for each module.
- internal/cmd: Command lines for execute the Rover.
- script: The rover related shell scripts.
    - build: For `make` command use.
    - check: Check the rover features is supported for the system.
    - debug: Generate the debug information for the programs.
    - release: Fot release the rover.
- test/e2e: E2E test to verify the Rover future.
```
.
├── CHANGES.md
├── cmd
├── configs
├── bpf
├── docker
├── docs
├── script
│   ├── build
│   ├── check
│   ├── debug
│   ├── release
├── pkg
│   ├── logger
│   ├── config
│   ├── module
│   ├── boot
│   ├── core
│   ├── process
│   ├── profiling
│   ├── tools
├── test
│   ├── e2e
├── internal
│   ├── cmd
```