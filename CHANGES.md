Changes by Version
==================
Release Notes.

0.8.0
------------------
#### Features
* Separate multiple process for reading connection information in the access log module.
* Add a delay time before delete the connection in the access log module.
* Fix context structs parameters for tracepoint programs.
* Improve the build of skywalking-rover by adding some options.
* Decode the BPF data by self instant `binary.Read` to reduce CPU usage.
* Fix the unaligned memory accesses for `upload_socket_data_buf`.
* Support for connecting to the backend server over TLS without requiring `ca.pem`.
* Fix missing the first socket detail event in HTTPS protocol.

#### Bug Fixes
* Fix the base image cannot run in the arm64.

#### Documentation
* Add a dead link checker in the CI.

#### Issues and PR
- All issues are [here](https://github.com/apache/skywalking/milestone/228?closed=1)
- All and pull requests are [here](https://github.com/apache/skywalking-rover/milestone/8?closed=1)

0.7.0
------------------
#### Features
* Upgrade LLVM to `18`.
* Support propagation the excluding namespaces in the access log to the backend.
* Add `pprof` module for observe self.
* Add detect process from `CRI-O` container in Kubernetes.
* Introduce `MonitorFilter` into access log module. 
* Support monitoring ztunnel to adapt istio ambient mode.
* Enhance get connection address strategy in access log module.
* Reduce file mount needs when deploy in the Kubernetes, split env name `ROVER_HOST_MAPPING` to `ROVER_HOST_PROC_MAPPING` and `ROVER_HOST_ETC_MAPPING`.

#### Bug Fixes
* Fixed the issue where `conntrack` could not find the Reply IP in the access log module.
* Fix errors when compiling C source files into eBPF bytecode on a system with Linux headers version 6.2 or higher.
* Fixed `ip_list_rcv` probe is not exist in older linux kernel.
* Fix concurrent map operation in the access log module.
* Fix the profiling cannot found process issue.
* Fix cannot translate peer address in some UDP scenarios.
* Fix the protocol logs may be missing if the process is short-lived.
* Fix some connections not called close syscall, causing unnecessary memory usage.

#### Documentation

#### Issues and PR
- All issues are [here](https://github.com/apache/skywalking/milestone/209?closed=1)
- All and pull requests are [here](https://github.com/apache/skywalking-rover/milestone/7?closed=1)

0.6.0
------------------
#### Features
* Enhance compatibility when profiling with SSL.
* Update `LabelValue` obtain pod information function to add default value parameter.
* Add `HasOwnerName` to judgement pod has owner name.
* Publish the `latest` Docker image tag.
* Improve the stability of Off CPU Profiling.
* Support collecting the access log from Kubernetes.
* Remove the scanner mode in the process discovery module.
* Upgrade Go library to `1.21`, eBPF library to `0.13.2`.
* Support using `make docker.debug` to building the debug docker image.

#### Bug Fixes

#### Documentation
* Update architecture diagram.
* Delete module design and project structure document.
* Adjust configuration modules during setup.

#### Issues and PR
- All issues are [here](https://github.com/apache/skywalking/milestone/185?closed=1)
- All and pull requests are [here](https://github.com/apache/skywalking-rover/milestone/6?closed=1)

0.5.0
------------------
#### Features
* Enhance the protocol reader for support long socket data.
* Add the syscall level event to the trace.
* Support OpenSSL 3.0.x.
* Optimized the data structure in BPF.
* Support continuous profiling.
* Improve the performance when getting `goid` in eBPF.
* Support build multiple architecture docker image: `x86_64`, `arm64`. 

#### Bug Fixes
* Fix HTTP method name in protocol analyzer
* Fixed submitting multiple network profiling tasks with the same uri causing the rover to restart

#### Documentation

#### Issues and PR
- All issues are [here](https://github.com/apache/skywalking/milestone/167?closed=1)
- All and pull requests are [here](https://github.com/apache/skywalking-rover/milestone/5?closed=1)

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
