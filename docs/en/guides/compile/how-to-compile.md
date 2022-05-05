# Compiling

## Go version

Go version `1.17` or higher is supported for compilation.

## Platform

### Linux

Linux version >= `4.4`, and dependency these tools:
1. `llvm` >= 13.
2. `libbpf-dev`.

### MacOS or Windows

Make sure it already has a docker environment.

## Command
```shell script
git clone https://github.com/apache/skywalking-rover
cd skywalking-rover
# Linux platform
make generate build
# MacOS or Windows
make container-generate build
```