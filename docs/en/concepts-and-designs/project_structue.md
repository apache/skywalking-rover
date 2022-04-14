# Project Structure
- cmd: The starter of Rover.
- configs: Rover configs.
- bpf: All the BPF programs with C code.
- pkg: Contains all modules and basic framework.
    - boot: Manage all enabled module life cycle.
    - config: Read config for start.
    - logger: Manage the log.
    - tools: Sharing tools for each module.
- script/build: For `make` command use.
- test/e2e: E2E test to verify the Rover future.
```
.
├── CHANGES.md
├── cmd
├── configs
├── docs
├── go.sum
├── script
│   ├── build
├── pkg
│   ├── boot
│   ├── config
│   ├── logger
│   ├── tools
│   ├── modules
├── test
│   ├── e2e
```