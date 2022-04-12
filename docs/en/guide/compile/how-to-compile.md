# Compiling

## Go version

Go version `1.17` or higher is supported for compilation.

## Platform
Linux is supported in the SkyWalking Rover.
If you want to compile the Rover in the macOS or Windows, please make sure it already has docker environment.

## Command
```shell script
git clone https://github.com/apache/skywalking-rover
cd skywalking-rover
# Linux platform
make generate build
# MacOS or Windows
make container-generate build
```