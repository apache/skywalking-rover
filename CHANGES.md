Changes by Version
==================
Release Notes.

0.4.0
------------------
#### Features
* Enhancing the render context for the Kubernetes process.
* Simplify the logic of network protocol analysis.
* Upgrade Go library to `1.18`, eBPF library to `0.9.3`.
* Make the Profiling module compatible with more Linux systems.

#### Bug Fixes

#### Documentation
* Adding support version of Linux documentation.

#### Issues and PR
- All issues are [here](https://github.com/apache/skywalking/milestone/154?closed=1)
- All and pull requests are [here](https://github.com/apache/skywalking-rover/milestone/4?closed=1)

0.3.0
------------------
#### Features
* Support `NETWORK` Profiling.
* Let the logger as a configurable module.
* Support analyze the data of OpenSSL, BoringSSL library, GoTLS, NodeTLS in `NETWORK` Profiling.
* Enhancing the kubernetes process finder.

#### Bug Fixes
* Fixed reading process paths incorrect when running as a container.
* Fix the crash caused by multiple profiling tasks.

#### Issues and PR
- All issues are [here](https://github.com/apache/skywalking/milestone/144?closed=1)
- All and pull requests are [here](https://github.com/apache/skywalking-rover/milestone/3?closed=1)

0.2.0
------------------
#### Features
* Support `OFF_CPU` Profiling.
* Introduce the `BTFHub` module.
* Update to using frequency mode to `ON_CPU` Profiling.
* Add logs in the profiling module logical.

#### Bug Fixes
* Fix `docker` based process could not be detected.

#### Issues and PR
- All issues are [here](https://github.com/apache/skywalking/milestone/134?closed=1)
- All and pull requests are [here](https://github.com/apache/skywalking-rover/milestone/2?closed=1)

0.1.0
------------------
#### Features
* Support detect processes in `scanner` or `kubernetes` mode.
* Support profiling C, C++, Golang, and Rust service.

#### Bug Fixes

#### Issues and PR
- All issues are [here](https://github.com/apache/skywalking/milestone/124?closed=1)
- All and pull requests are [here](https://github.com/apache/skywalking-rover/milestone/1?closed=1)