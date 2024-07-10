# Pprof 

Pprof is a feature to collect self runtime profiling data through `pprof` module.

## Configuration

| Name      | Default | Environment Key      | Description                         |
|-----------|---------|----------------------|-------------------------------------|
| `enabled` | `false` | `ROVER_PPROF_ACTIVE` | Enable pprof module.                |
| `port`    | `6060`  | `ROVER_PPROF_PORT`   | The HTTP port to expose pprof data. |

## Expose Paths

- `/debug/pprof/`: The root path to access pprof data.
- `/debug/pprof/cmdline`: The command line invocation of the current program.
- `/debug/pprof/profile`: A pprof-formatted snapshot of the current program.
- `/debug/pprof/symbol`: The symbol table of the current program.
- `/debug/pprof/trace`: A trace of the current program.