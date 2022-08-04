// Licensed to Apache Software Foundation (ASF) under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Apache Software Foundation (ASF) licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#define CONNECTION_ROLE_TYPE_UNKNOWN 0
#define CONNECTION_ROLE_TYPE_CLIENT 1
#define CONNECTION_ROLE_TYPE_SERVER 2
// active connection cached into the hashmap
// if connection closed, then deleted
struct active_connection_t {
    // random value in one active connection
    // generate a unique ID through connection_id + random_id, which is convenient for histogram data storage
    __u64 random_id;
    // process id
    __u32 pid;
    // socket fd under process
    __u32 sockfd;
    // the type of role in current connection
    __u32 role;
    // socket type
    __u32 socket_family;

    // remote address
    __u32 remote_addr_v4;
    __u8 remote_addr_v6[16];
    __u32 remote_port;
    // local address
    __u32 local_addr_v4;
    __u8 local_addr_v6[16];
    __u16 local_port;

    // basic stats(bytes, avg(exe_time/count))
    __u64 write_bytes;
    __u64 write_count;
    __u64 write_exe_time;
    __u64 read_bytes;
    __u64 read_count;
    __u64 read_exe_time;

    // RTT when write
    __u64 write_rtt_count;
    __u64 write_rtt_time;

    // for protocol analyze
    __u32 protocol;
    __u32 fix;
    __u64 prev_count;
    char prev_buf[4];
    __u32 prepend_length_header;
    // current connection is ssl
    __u32 ssl;

    // connect event already send
    __u32 connect_event_send;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct active_connection_t);
} active_connection_map SEC(".maps");
static __inline __u64 gen_tgid_fd(__u32 tgid, __u32 sockfd) {
    return ((__u64)tgid << 32) | sockfd;
}

// notify to the user-space the connection connected(connect, accept)
// only traced connection ipv4/v6 or unknown connection
struct socket_connect_event_t {
    // current connection id
    __u64 conid;
    // random value in one active connection
    // generate a unique ID through connection_id + random_id, which is convenient for histogram data storage.
    // we need random_id becase socketfd would be multiplexed in the same pid,
    // but the metrics data(histogram) is MAP data, which can only be read by user-space with interval, so it would cause data delay.
    __u64 random_id;
    // the duration of connect or connect, if unknown role then return 0
    __u64 exe_time;
    // is need to complete the address information
    __u32 need_complete_addr;
    // current process id
    __u32 pid;
    // current socket fd
    __u32 sockfd;
    // create from function name
    __u32 func_name;

    // the type of role in current connection
    __u32 role;
    // socket type
    __u32 socket_family;
    // upstream
    __u32 remote_addr_v4;
    __u8 remote_addr_v6[16];
    __u32 remote_port;
    // downstream
    __u32 local_addr_v4;
    __u8 local_addr_v6[16];
    __u16 local_port;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_connection_event_queue SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct socket_connect_event_t);
    __uint(max_entries, 1);
} socket_connect_event_per_cpu_map SEC(".maps");
static __inline struct socket_connect_event_t* create_socket_connect_event() {
  __u32 kZero = 0;
  return bpf_map_lookup_elem(&socket_connect_event_per_cpu_map, &kZero);
}

struct socket_close_event_t {
    // current connection id
    __u64 conid;
    // random value in one active connection
    // generate a unique ID through connection_id + random_id, which is convenient for histogram data storage
    __u64 random_id;

    // close event execute time
    __u64 exe_time;
    // process id
    __u32 pid;
    // socket fd under process
    __u32 sockfd;
    // the type of role in current connection
    __u32 role;
    // the protocol type of the connection
    __u32 protocol;
    // the connection is ssl
    __u32 ssl;
    __u32 fix;

    // socket type
    __u32 socket_family;
    // upstream
    __u32 remote_addr_v4;
    __u8 remote_addr_v6[16];
    __u32 remote_port;
    // downstream
    __u32 local_addr_v4;
    __u8 local_addr_v6[16];
    __u16 local_port;
    __u32 fix1;

    // basic stats(bytes, avg(exe_time/count))
    __u64 write_bytes;
    __u64 write_count;
    __u64 write_exe_time;
    __u64 read_bytes;
    __u64 read_count;
    __u64 read_exe_time;

    // RTT when write
    __u64 write_rtt_count;
    __u64 write_rtt_time;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_close_event_queue SEC(".maps");

// histogram stats
#define SOCKET_CONNECTION_STATS_HISTOGRAM_DATA_TYPE_RTT 1       // RTT
#define SOCKET_CONNECTION_STATS_HISTOGRAM_DATA_TYPE_EXE_TIME 2  // Execute time
struct socket_connection_histogram_key_t {
    // conid + random_id = unique id
    __u64 conid;
    __u64 random_id;
    // ingress, egress
    __u32 data_direction;
    // RTT, Execute time, etc.
    __u32 data_type;
    // histogram bucket
    __u64 bucket;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct socket_connection_histogram_key_t);
	__type(value, __u32);
} socket_connection_stats_histogram SEC(".maps");
#define HISTOGRAM_MILLI_TOTAL_BUCKETS 34
// 0ms, 0.01ms, 0.05ms, 0.1ms, 0.5ms, 1ms, 1.2ms, 1.5ms, 1.7ms, 2ms, 2.5ms, 3ms, 5ms, 7ms, 10ms, 13ms, 16ms, 20ms, 25ms, 30ms, 35ms, 40ms, 45ms, 50ms, 70ms, 100ms, 150ms, 200ms, 300ms, 500ms, 1s, 2s, 3s, 5s
__u64 histogram_milli_buckets[HISTOGRAM_MILLI_TOTAL_BUCKETS] = {0, 10000, 50000, 100000, 500000, 1000000, 1200000, 1500000, 1700000, 2000000, 2500000, 3000000, 5000000, 7000000, 10000000, 13000000, 16000000, 20000000, 25000000, 30000000, 35000000, 40000000,
    45000000, 50000000, 70000000, 100000000, 150000000, 200000000, 300000000, 500000000, 1000000000, 2000000000, 3000000000, 5000000000};
static __inline void add_to_socket_connection_stats_histogram(__u64 conid, __u64 random_id, __u32 direction, __u32 type, __u64 value) {
    // RTT from us to ns
    if (type == SOCKET_CONNECTION_STATS_HISTOGRAM_DATA_TYPE_RTT) {
        value *= 1000;
    }
    __u64 bucket = HISTOGRAM_MILLI_TOTAL_BUCKETS - 1;
    for(__u64 inx = 1; inx < HISTOGRAM_MILLI_TOTAL_BUCKETS - 1; inx = inx + 1) {
        if (histogram_milli_buckets[inx] > value) {
            bucket = inx - 1;
            break;
        }
    }
    struct socket_connection_histogram_key_t key = {};
    key.conid = conid;
    key.random_id = random_id;
    key.data_direction = direction;
    key.data_type = type;
    key.bucket = bucket;
    __u32 *val;
    val = bpf_map_lookup_elem(&socket_connection_stats_histogram, &key);
    if (!val) {
        __u32 count = 0;
        bpf_map_update_elem(&socket_connection_stats_histogram, &key, &count, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&socket_connection_stats_histogram, &key);
        if (!val)
            return;
    }
    (*val) += 1;
}

#define SOCKET_EXCEPTION_OPERATION_TYPE_RETRANSMIT 1
#define SOCKET_EXCEPTION_OPERATION_TYPE_DROP 2
struct socket_exception_operation_event_t {
    __u32 pid;
    // socket type
    __u32 socket_family;
    // remote
    __u32 remote_addr_v4;
    __u8 remote_addr_v6[16];
    __u32 remote_port;
    // local
    __u32 local_addr_v4;
    __u8 local_addr_v6[16];
    __u16 local_port;
    // operation type
    __u32 type;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_exception_operation_event_queue SEC(".maps");

// openssl read or write
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_data_args_t);
} openssl_sock_data_args SEC(".maps");