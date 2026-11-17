Changes by Version
==================
Release Notes.

0.8.0
------------------
#### Features
* Fix HTTP/2 access log parsing: preface and SETTINGS inference, HPACK per direction, CONTINUATION, padding, trailers, frame bounds. h2c and gRPC produced no access logs before.
* Report the socket data events the HTTP/2 parser drops, so an analyzer that carries the kernel level detail in those events does not lose the bytes of the call.
* Consume HTTP/1 bodies of a known length as their socket data arrives: every event is released immediately and kept as a metadata-only copy for the kernel log details.
* Fix HTTP/1 messages never completing when BPF truncated their socket call, bodiless responses swallowing a keep-alive connection, and an incomplete body reported as complete with size 0.
* Fix the buffer corrupting data that spans two socket events, keeping a stale skip offset, reading from an expired element and scanning from the front for out-of-order events.
* Fix the socket data upload copying only `size & 0x7ff` bytes per chunk, and `writev`/`sendmsg` re-reading one iov entry while dropping the others, both with no truncation signal.
* Raise `access_log.protocol_analyze.per_cpu_buffer` to 4MB: 1MB held about 50 socket data events per CPU, so a busy reader dropped samples and HTTP/2 lost whole connections.
* Add memory protection: the socket data events held in memory may take at most `max_memory_percent` (default 80) of the memory the agent can be allocated (its cgroup limit, else the memory of the host); a new event is dropped (counted) while they hold it, and the connection it belonged to releases its cut message and restarts at its next message. `max_memory` is removed. The Go soft memory limit is set to 90% of that memory unless GOMEMLIMIT is set.
* Analyze a partition once `protocol_analyze.trigger_events` (default 1000) events are pending instead of only on the flush period, visiting the connections that received data.
* Protect the per connection protocol maps with a lock and account the events an analyzer holds outside the connection buffer, so removing a closed connection does not leak them.
* Add `access_log.flush.merge_kernel_logs` (default off): report one kernel log per operation of a message instead of one per syscall, with the counters summed.
* Queue at most one analysis pass started by `trigger_events`, instead of one goroutine per event above the trigger count.
* Bound the HTTP/2 SETTINGS inference by the max frame size instead of six settings, so a peer sending more is still recognized.
* Accept `auto` (or 0) for `access_log.{connection,protocol}_analyze.analyze_parallels`: 2 x GOMAXPROCS bounded to [2, 10], logged at startup.
* Send the access logs over `access_log.sender.parallelism` streams at once (default 8 instead of the single stream), at most `sender.max_logs_per_send` logs per stream (default 2000), stop sending until the next batch when a send fails, and drop the oldest waiting batches past `sender.max_pending_logs` (default 200000, 0 for unbounded).
* Encode the access logs with a protobuf encoder of their own when they can no longer change, and keep them as bytes until they are sent: the stream sends the bytes `proto.Marshal` gives, without the reflection of the generic marshaling, and the waiting logs are no longer message trees. A log with a string that is not UTF-8 is dropped alone (`rover_access_log_encode_errors_total`) instead of failing its stream.
* Read every perf ring with one goroutine: `parse_parallels` above 1 is ignored (default 1), the library serialised those readers and they could deliver the events of a connection out of order.
* Add `access_log.event_reader` (`wakeup_events` 32, `flush_period` 1s, `batch_size` 64 by default; 0 turns waking and batching off): wake the reader of the socket data and connection rings once per several events, flushed periodically, and hand the events to the partitions in batches, delivered within `flush_period`.
* Fix a crash of the buffer: appending a socket data event read the reading position that the analysis moves without the event lock.
* Build the arguments of the per event debug logs only when the debug level is enabled.
* Add `access_log.protocol_analyze.drop_h2c_unused_frame` (default off): the BPF side follows the frames of cleartext HTTP/2 connections and does not upload the socket calls that carry only WINDOW_UPDATE, PING, PRIORITY or SETTINGS ACK frames.
* Add `access_log.protocol_analyze.skip_h2c_data_payload` (default off): the BPF side uploads a socket call of a cleartext HTTP/2 connection that lies wholly inside the payload of a DATA frame as an event without content that carries its size (the new `payload_skipped` field of the socket data event), and the HTTP/2 parser counts it into the body without reading it. A DATA payload that runs on past a socket call truncated by the upload limit is now followed into the next call instead of being resynchronized.
* Add `access_log.protocol_analyze.skip_http1_body_payload_bpf` (default off): the BPF side follows the message heads and bodies of cleartext HTTP/1 connections (Content-Length, chunked, delimited by the close) and uploads a socket call that lies wholly inside a Content-Length body or inside the data of a chunk, or that comes behind the head of a response delimited by the close, as an event without content that carries its size, which the HTTP/1 parser counts into the body; with `access_log.flush.merge_kernel_logs` on, the consecutive skipped calls of a body are uploaded as one event that carries the span of their data ids.
* Make the data id of a socket call unique when calls of one fd run at once (an atomic add, and a claim of the id when another call is in flight), and count the calls of an fd in flight: a call that returns alone on its fd is known to upload after every call with a smaller data id. The count is kept per socket call for an event layout to carry, and the HTTP/1 body skipping of the user space uses it to forget the data ids of the calls that uploaded nothing (`http1skip.Call.InFlight`).
* Expose the agent's own state on the pprof server as `/metrics`: pending and held socket data events, analysis passes and their age, flush and send queue depths.
* Release the socket data events that are dropped before an analyzer sees them (read error, filtered connection, no analyzer, buffer clean), instead of leaving them to the collector.
* Merge the kernel logs of a message when it is finished instead of when it is flushed, so the unmerged records never enter the flush queue.
* Change the socket data event of the access log (bpf/accesslog/include/socket_data_event.h): the details of a socket call (function, L4 counters, ssl, ports, calls in flight) travel in its data event, a call whose content is not uploaded still sends one without content, and no detail event is sent. The kernel logs carry the L4 package count and size of the calls; the L2/L3 metrics come from an event of their own (`access_log.kernel_metrics.l2_l3`).
* Add `access_log.kernel_metrics.l2_l3` (default on): the L2/L3 programs (bpf/accesslog/l24) attach only with it on, and the exit of a socket call sends its L2/L3 details (interface, IP layer, netfilter, neighbour resolution and device queue times, L4 duration and retransmits, the packages `__tcp_transmit_skb` sent) in an event of their own, which the kernel log of the call takes by its connection and data id; off, those programs are loaded as stubs and the socket data event is unchanged. The merge of the kernel logs keeps the interface in its key and sums every restored metric. The sk_buff receive and transmit maps are LRU maps, so the sk_buffs never copied to a reader no longer fill them.
* Remove the metrics `rover_memory_usage_bytes`, `rover_memory_threshold_bytes` and `rover_memory_protection_active` of the memory protection: it is measured by `rover_socket_data_inflight_bytes` against `rover_socket_data_inflight_budget_bytes` and `rover_memory_limit_bytes`, and `rover_socket_data_pressure` (with `rover_socket_data_pressure_changes_total`) tells when the kernel sends the socket calls without their data.
* The start time of an HTTP/2 access log is the first socket call of the request HEADERS (it was the first call of the request body when there was one).
* The L2 total package size of a read kernel log is the bytes copied to the reader by the call (`skb_copy_datagram_iovec`) instead of the whole length of the sk_buff summed on every copy from it.
* Add the per-CPU batching of the skipped and tail-cut HTTP/2 calls (`access_log.protocol_analyze.batch_h2c_records`) and the per stream summaries of the skipped DATA payload calls (`summarize_h2c_payload`), both default off.
* Add `access_log.protocol_analyze.skip_http1_body_payload` (default off): a socket call of an HTTP/1 connection that lies wholly inside a Content-Length body is decoded without its bytes (the parser only counts them), so it takes no data buffer.
* Hold the logs of a connection whose destination the ztunnel lb mapping has not resolved yet for at most the resolution grace period (`accesslog.Options.DisableResolutionDefer` turns it off for an agent).
* Add `accesslog.Options.DisableSendMultipleProtocols`: a protocol log goes without the kernel logs of its message (still told to `OnProtocolLog`).
* Add `access_log.bpf.attach_mode` and `access_log.bpf.nat_hook` (default `auto`): the socket call programs attach from BPF trampolines or raw tracepoints where the kernel runs them, and the remote address behind a DNAT is read at the confirmation of the conntrack entry.
* Add `access_log.protocol_analyze.analyze_trace_context` (default on): the HTTP logs carry the sw8 and b3 tracing context of their requests.
* Add extension points for an agent built on the access log: the protocol recognition and the connection filter rule of the BPF side (bpf/include/protocol_analyzer_ext.h, connection_filter_rule.h), the extra protocols of the analysis (`collector.NewTransferCollector`) and the runner options (`accesslog.NewRunnerWithOptions`).
* Add the HTTP/2 access log E2E test (h2c, gRPC unary, streaming and trailers-only, HTTP/2 over TLS), also running on the Istio ambient data path.
* Separate multiple process for reading connection information in the access log module.
* Add a delay time before delete the connection in the access log module.
* Fix context structs parameters for tracepoint programs.
* Improve the build of skywalking-rover by adding some options.
* Decode the BPF data by self instant `binary.Read` to reduce CPU usage.
* Fix the unaligned memory accesses for `upload_socket_data_buf`.
* Support for connecting to the backend server over TLS without requiring `ca.pem`.
* Fix missing the first socket detail event in HTTPS protocol.
* Support parallel parsing protocol data in the access log module.
* Upgrade Go library to `1.22`, eBPF library to `0.16.0`.
* Reduce missing details issue in the access log module.
* Improve HTTP/1.x protocol parsing strategy to encase missing data.
* Add gRPC sender to sending the access log to the backend.
* Add warning log when the event queue almost full in the access log module.
* Reduce unessential `conntrack` query when detect new connection.
* Reduce CPU and memory usage in the access log module.
* Reduce handle connection event time in the access log module.
* Downgrade the protocol of connection when protocol break in the access log module.
* Bump up go version to `1.24` and eBPF library to `0.18.0`.
* Support detect ztunnel environment in the inbound request.
* Increase the transmit buffer size in the network profiling and access log module.
* Reduce eBPF verifier complexity by converting hot inline helpers to BPF-to-BPF calls, fixing the "program too large" failure when loading access log programs on newer kernels.
* Reduce memory by not retaining ELF symbols for processes that are not being profiled.
* Increase the default access log protocol per-CPU buffer to 1MB to reduce dropped samples.
* Aggregate dropped perf event sample warnings periodically instead of logging every burst.
* Lower the log level for connection query errors of short-lived exited processes.
* Enable pprof by default but bind it to 127.0.0.1 so it is not exposed on the network.
* Support collecting the ztunnel outbound connection mappings from the ztunnel admin config dump, as a symbol-independent fallback of the uprobe based events in the access log module.
* Support cross-checking the ztunnel proxied connection count from the ztunnel prometheus metrics in the access log module.
* Report a periodic info-level summary of un-resolved remote addresses, including the conntrack and ztunnel correlation statistics, in the access log module.
* Attach all matched ztunnel `track_outbound` symbol copies when attaching the uprobe in the access log module.
* Add success/failure counters to the conntrack real peer address queries.
* Support monitoring short-lived processes in the access log module.
* Read ztunnel connection peer identities via an eBPF uprobe on `ConnectionResult::record_internal`, with a build-id offset table and access-log fallback.
* Support unwinding the user space stack by the call frame information(`.eh_frame`) in the ON_CPU/OFF_CPU profiling, fixing the missing frames when the binaries/libraries are built without the frame pointer. The `profiling.task.user_stack_unwind` config(`auto` by default) decides the unwinding way per process.

#### Bug Fixes
* Fix `Buffer.Len` summing the first event's length once per event instead of each event's length (the profiling HTTP/1 body length).
* Fix a receive made with `MSG_PEEK` being parsed as received data (an HTTP/2 header block decoded twice desynchronized HPACK) and stopping the h2c and HTTP/1 frame followers: it is uploaded without its bytes, outside the chain of the uploads, and reported as the kernel log of its call alone.
* Fix the h2c upgrade of an HTTP/1.1 connection losing its first stream: the head reader keeps the Upgrade and HTTP2-Settings headers.
* Fix the base image cannot run in the arm64.
* Fix process fork tracepoint reporting thread TID instead of process TGID, causing repeated process detected/dead churn.
* Fix panic in the access log module when handling HTTP/2 streams without a body.
* Fix the ztunnel event reader and process finder not being registered when the ztunnel process starts after the rover.
* Fix ghost connections created by failed accept syscalls with a negative socket fd in the access log module.
* Remove the ineffective `ctnetlink_fill_info` kprobe and fix an always-true condition in the conntrack BPF program.
* Bump up `google.golang.org/grpc` to `1.84.0` to fix CVE-2026-33186 (authorization bypass via malformed `:path` header), and replace the deprecated `golang.org/x/net/context` with the standard library `context`.
* Bump up `golang.org/x/net` to `0.61.0` to fix GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6612, and GO-2026-6617 (CVE-2026-78659, CVE-2026-78660, CVE-2026-78669, CVE-2026-78663, and CVE-2026-97032), and `golang.org/x/text` to `0.43.0` to fix GO-2026-6629 (CVE-2026-56851).
* Ignore absent ztunnel principal offsets when decoding full-window identity samples.
* Bump up `github.com/cilium/ebpf` to `0.22.0` to fix CVE-2026-10722 (integer overflow via `LoadCollectionSpecFromReader`).
* Bump up `golang.org/x/net` to `0.62.0` to fix GO-2026-6860 and GO-2026-6866 (CVE-2026-78661 and CVE-2026-97045).

#### Documentation
* Add a dead link checker in the CI.
* Bump up Kubernetes libraries to `0.29.15`.

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
