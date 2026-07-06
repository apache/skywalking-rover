# Pprof 

Pprof is a feature to collect self runtime profiling data through `pprof` module.

## Configuration

| Name      | Default     | Environment Key      | Description                                                                        |
|-----------|-------------|----------------------|------------------------------------------------------------------------------------|
| `enabled` | `true`      | `ROVER_PPROF_ACTIVE` | Enable pprof module.                                                                |
| `host`    | `127.0.0.1` | `ROVER_PPROF_HOST`   | The bind host of the pprof HTTP server, only listens on the local host by default. |
| `port`    | `6060`      | `ROVER_PPROF_PORT`   | The HTTP port to expose pprof data.                                                |

## Expose Paths

- `/debug/pprof/`: The root path to access pprof data.
- `/debug/pprof/cmdline`: The command line invocation of the current program.
- `/debug/pprof/profile`: A pprof-formatted snapshot of the current program.
- `/debug/pprof/symbol`: The symbol table of the current program.
- `/debug/pprof/trace`: A trace of the current program.