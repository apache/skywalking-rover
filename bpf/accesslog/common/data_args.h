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

#pragma once

#include "socket_opts.h"
#include "socket_data.h"
#include "../process/process.h"

struct connect_track_remote {
    __u64 iph;
    __u64 ipl;
    __u16 port;
};

struct sock_data_args_t {
    __u32 fd;
    // current read/write is calls on the sockets.
    __u16 is_sock_event;
    // the receive flags that leave the received bytes in the socket or discard them (MSG_PEEK, MSG_TRUNC):
    // such a call does not hand the bytes it reports to the reader. Set by the security_socket_recvmsg
    // kprobe, only read by syscalls/h2c.h.
    __u16 recv_flags;
    size_t iovlen;
    unsigned int* msg_len;
    __u64 start_nacs;
    // buffer
    char* buf;
    struct iovec *iovec;
    __u64 data_id;
    // the generator entry the data id was taken from (socket_data_id_t.epoch): the call is counted in its
    // in_flight from the enter until socket_data_call_leave, 0 when it is not counted
    __u64 data_id_epoch;
    // the socket calls of the fd that were in flight when the call returned, itself included, those of its
    // direction (itself included) and those of the other direction (see socket_data_call_observe); 0 for the
    // first two when it is not known, 0xff for the last
    __u16 in_flight;
    __u8 in_flight_direction;
    __u8 in_flight_other;
    // the data direction (SOCK_DATA_DIRECTION_*) the call is counted in
    __u8 call_direction;
    // 1 from the enter of the call to its exit, 0 once the exit is done: the entry of a thread stays in
    // socket_data_args between its calls (see socket_data_args_get)
    __u8 active;
    // set by the exit of a call of a connection followed as HTTP/2 (syscalls/transfer.h): its leave marks the
    // generator entry of the fd so the later calls of the fd are not counted in flight (socket_data_id_t.no_flight)
    __u8 no_flight_mark;
    // for openssl
    __u32 excepted_size;
    __u32 ifindex;
    __u64 total_package_size;
    __u8 package_count;
    __u8 retransmit_package_count;
    __u8 ssl_buffer_force_unfinished;
    __u8 sk_role;
    __u32 l2_enter_queue_count;
    // the socket the role of the call is read from at its exit, only when the call makes the connection
    // (get_or_create_active_conn): the first sk_buff copy of a receive and tcp_sendmsg of a send note it while the
    // role is not known
    void *role_sk;
    // the end of the call (bpf_ktime_get_ns at its exit), 0 until the exit read it: the exit reads it
    // once it knows the call keeps it (syscalls/transfer.h process_write_data, h2c_fast_now). Kept here rather than in
    // a register so the paths that read it and those that do not leave the verifier the same state.
    __u64 exit_nacs;
    // the fields from here on are the L2 to L4 details of the call (access_log.kernel_metrics.l2_l3, see l24/l24.h): only
    // the programs of l24/ write them, and only the l24 event of the call reads them (l24_upload). The enter of a call
    // does not zero them: the first l24 program of a call does (l24_args_own), which marks them with the start of the
    // call (l24_stamp), and they are the call's only while the mark is its start. So the enter of a call is the same
    // with the switch on or off, and touches the last cache lines of the thread slot as before.
    __u64 l24_stamp;
    // the sk_buff of the __ip_queue_xmit in progress
    struct sk_buff *buffer;
    // the enter of tcp_sendmsg in progress
    __u64 enter_l4_time;
    // write: the time in tcp_sendmsg; read: the time in tcp_v4_rcv/tcp_v6_rcv of the sk_buffs copied
    __u64 l4_duration;
    __u64 l3_duration;
    // write: the time from ip_output to ip_finish_output2; read: the time from ip_rcv to ip_rcv_finish
    __u64 l3_output_rcv_duration;
    __u64 l3_local_duration;
    __u32 total_resolve_mac_count;
    __u32 total_net_filter_count;
    __u64 total_resolve_mac_time;
    __u64 total_net_filter_time;
    __u64 total_package_to_queue_time;
    __u64 total_package_receive_from_queue_time;
    __u64 l2_duration;
    // the sk_buffs __tcp_transmit_skb sent while the call was in progress and their bytes
    __u32 l4_transmit_package_count;
    __u32 l4_transmit_package_size;
    __u64 l2_ready_send_duration;
    __u64 l2_send_duration;
};
// What the enter of a call zeroes of its arguments (socket_data_call_begin): nothing reads the fields from l24_stamp on
// before an l24 program zeroed them for the call (l24_args_own). Zeroing the first bytes up to there (112) instead of the
// 240 of the whole struct leaves the last cache lines of the thread slot untouched.
#define SOCK_DATA_ARGS_ZERO_LEN __builtin_offsetof(struct sock_data_args_t, l24_stamp)
// kernel_metrics_l2_l3 is a constant of the load (access_log.kernel_metrics.l2_l3, set by the loader): with it on, the
// programs of l24/ are attached and fill the L2 to L4 details of the socket calls, which the exit of a call sends in an
// event of its own (l24_upload, socket_l24_queue). With it off the verifier drops the branch of the exit on it, and the
// programs of l24/ are loaded as stubs.
volatile const __u32 kernel_metrics_l2_l3;
// The arguments of the socket call a thread (pid_tgid) is in, from its enter to its exit. The entry of a thread
// stays between its calls, only marked inactive (active = 0) when the exit is done, and the next enter of the
// thread writes its arguments over it in place: an update and a delete of a hash map entry per call cost several
// times a lookup and a store. Every reader takes the entry through socket_data_args_get, which gives an inactive
// one as missing, so the map holds for the readers exactly what it held when the exit deleted the entry. The
// entries of the threads that are not in a call are deleted when the thread exits
// (tracepoint_sched_process_exit); the entry of a thread that died in a call stays active, as it stayed before.
// A plain hash map (not an LRU): no entry, active or not, is ever evicted, and a full map refuses the entry of a
// new thread as it refused the arguments of a call before, so the map holds the threads of the traced processes
// that made a socket call and are still alive, besides the active entries of the dead ones.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65535);
	__type(key, __u64);
	__type(value, struct sock_data_args_t);
} socket_data_args SEC(".maps");

// The thread slots. The arguments of a thread's socket calls live in a slot of an array indexed by its thread id
// (socket_data_args_slots, slot tid % SOCK_ARGS_SLOTS) instead of socket_data_args: an array lookup is inlined by the
// verifier and takes no hash and no bucket lock, and every socket call reads the arguments four times or more (enter,
// security_socket_*, skb copies, tcp_sendmsg, exit). The slot holds what the hash entry held, for the same life:
//  - a thread owns a slot from the enter of its first socket call until it exits (tracepoint_sched_process_exit
//    releases it when no call is active, as the hash entry was deleted; a thread that died in a call keeps it, as it
//    kept its active entry);
//  - the slot is tagged with the owner's pid_tgid (one 8 byte store), and only the owner writes that tag, so a thread
//    finds its arguments in its slot exactly when the tag is its own: they are then nowhere else;
//  - a slot is claimed by an insert of its index into socket_data_args_slot_owner (BPF_NOEXIST: one claimer wins, the
//    kernels before 5.12 have no compare-and-exchange), once per thread, and released by its delete (the tag is
//    cleared first);
//  - a thread whose slot another thread holds keeps its arguments in socket_data_args, and only ever there (it never claims a slot while it has an entry: the entry is looked up first while
//    socket_data_args_hash_live says the map is not empty). The big exit programs work on a copy of such an entry in
//    a work slot of the CPU (socket_data_args_exit_get) and write it back when they are done
//    (socket_data_call_done): every pointer to the arguments in an exit then points into the one array, which the
//    verifier walks once, where pointers into two maps would make it walk the exit twice.
// Capacity: the slots add to the 65535 entries of the hash map (a host with more live traced threads than the map
// held refused the arguments of the newest ones before). A machine with more than SOCK_ARGS_WORK_SLOTS possible CPUs
// does not trace the exits of the threads in the hash map on the CPUs beyond.
#define SOCK_ARGS_SLOTS 65536
#define SOCK_ARGS_WORK_SLOTS 4096
#define SOCK_ARGS_SLOT_OWN 0
#define SOCK_ARGS_SLOT_WORK 1
// A slot is 256 bytes and the array is mmapable, whose values start on a page: every slot then starts on a
// cache line, and the tag with the part of the arguments every call writes and reads (the first
// SOCK_DATA_ARGS_ZERO_LEN bytes, through exit_nacs) lie in two cache lines. With the 248 bytes of the slot before, six
// slots in eight had that part over three lines, each one an LLC miss more on the enter of a call (whose arguments
// were evicted by the copies of the calls in between). BPF_F_MMAPABLE (5.5) changes nothing else of the array.
#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif
struct sock_data_args_slot_t {
    // the pid_tgid of the owner (of the thread whose entry a work slot holds), 0 when free
    __u64 tag;
    // SOCK_ARGS_SLOT_OWN or SOCK_ARGS_SLOT_WORK
    __u64 kind;
    // (240 bytes with exit_nacs, which makes the slot 256)
    struct sock_data_args_t args;
};
_Static_assert(sizeof(struct sock_data_args_slot_t) == 256, "a thread slot is 256 bytes, four cache lines");
_Static_assert(__builtin_offsetof(struct sock_data_args_slot_t, args) + __builtin_offsetof(struct sock_data_args_t, l24_stamp) <= 128,
               "the tag and the arguments every call uses lie in the first two cache lines of a slot");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SOCK_ARGS_SLOTS + SOCK_ARGS_WORK_SLOTS);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, struct sock_data_args_slot_t);
} socket_data_args_slots SEC(".maps");
// the claims of the slots: slot index -> owner pid_tgid
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SOCK_ARGS_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} socket_data_args_slot_owner SEC(".maps");
// Never fewer than the entries of socket_data_args (an insert that made one adds 1, a delete that removed one takes 1):
// while it is 0 a thread without a slot has no entry and no lookup is made. Only a thread looks up its own entry,
// after the insert that made it. Written by the inserts and deletes, read by every call: apart from the flags of
// .bss, as conecting_args_live (common/connection.h).
#ifndef ACCESSLOG_LIVE_COUNTER
#define ACCESSLOG_LIVE_COUNTER __attribute__((section(".data.live"), aligned(64)))
#endif
volatile __u32 socket_data_args_hash_live ACCESSLOG_LIVE_COUNTER = 0;

static __always_inline struct sock_data_args_slot_t *socket_data_args_slot(__u64 id) {
    __u32 index = (__u32)id & (SOCK_ARGS_SLOTS - 1);
    return bpf_map_lookup_elem(&socket_data_args_slots, &index);
}

// socket_data_args_get gives the arguments of the socket call the thread is in, NULL when it is in none: in the
// thread's slot or in socket_data_args (the small programs: they may get a pointer into either map)
static __always_inline struct sock_data_args_t *socket_data_args_get(__u64 *id) {
    // (a thread of a process that was never monitored has no entry: no lookup, process/process.h)
    if (!process_may_be_monitored((__u32)(*id >> 32))) {
        return NULL;
    }
    struct sock_data_args_slot_t *slot = socket_data_args_slot(*id);
    if (slot != NULL && slot->tag == *id) {
        return slot->args.active != 0 ? &slot->args : NULL;
    }
    if (socket_data_args_hash_live == 0) {
        return NULL;
    }
    struct sock_data_args_t *args = bpf_map_lookup_elem(&socket_data_args, id);
    if (args != NULL && args->active == 0) {
        return NULL;
    }
    return args;
}

// socket_data_args_exit_get is socket_data_args_get for the exit programs: the arguments of a thread without a slot
// are copied into the work slot of the CPU, which socket_data_call_done writes back (see above). A program runs on
// one CPU without preemption and no program of interrupt context reads the arguments, so the work slot is the
// program's own until it ends.
static __always_inline struct sock_data_args_t *socket_data_args_exit_get(__u64 *id) {
    if (!process_may_be_monitored((__u32)(*id >> 32))) {
        return NULL;
    }
    struct sock_data_args_slot_t *slot = socket_data_args_slot(*id);
    if (slot == NULL) {
        return NULL;
    }
    if (slot->tag == *id) {
        return slot->args.active != 0 ? &slot->args : NULL;
    }
    if (socket_data_args_hash_live == 0) {
        return NULL;
    }
    struct sock_data_args_t *entry = bpf_map_lookup_elem(&socket_data_args, id);
    if (entry == NULL || entry->active == 0) {
        return NULL;
    }
    __u32 work = SOCK_ARGS_SLOTS + bpf_get_smp_processor_id();
    if (work >= SOCK_ARGS_SLOTS + SOCK_ARGS_WORK_SLOTS) {
        return NULL;
    }
    struct sock_data_args_slot_t *copy = bpf_map_lookup_elem(&socket_data_args_slots, &work);
    if (copy == NULL) {
        return NULL;
    }
    __builtin_memcpy(&copy->args, entry, sizeof(*entry));
    copy->tag = *id;
    copy->kind = SOCK_ARGS_SLOT_WORK;
    return &copy->args;
}

// socket_data_args_commit writes the work copy an exit worked on back into the thread's entry
static __always_inline void socket_data_args_commit(__u64 id, struct sock_data_args_t *args) {
    struct sock_data_args_slot_t *slot = (struct sock_data_args_slot_t *)((char *)args - __builtin_offsetof(struct sock_data_args_slot_t, args));
    if (slot->kind != SOCK_ARGS_SLOT_WORK) {
        return;
    }
    struct sock_data_args_t *entry = bpf_map_lookup_elem(&socket_data_args, &id);
    if (entry != NULL) {
        __builtin_memcpy(entry, args, sizeof(*entry));
    }
}

// socket_data_args_release gives up the thread's slot or entry when the thread exits, unless a call of it is active
// (tracepoint_sched_process_exit)
static __always_inline void socket_data_args_release(__u64 id) {
    if (!process_may_be_monitored((__u32)(id >> 32))) {
        return;
    }
    struct sock_data_args_slot_t *slot = socket_data_args_slot(id);
    if (slot != NULL && slot->tag == id) {
        if (slot->args.active == 0) {
            // (the tag first: a claimer only wins once the owner entry is gone)
            *(volatile __u64 *)&slot->tag = 0;
            __u32 index = (__u32)id & (SOCK_ARGS_SLOTS - 1);
            bpf_map_delete_elem(&socket_data_args_slot_owner, &index);
        }
        return;
    }
    if (socket_data_args_hash_live == 0) {
        return;
    }
    struct sock_data_args_t *entry = bpf_map_lookup_elem(&socket_data_args, &id);
    if (entry != NULL && entry->active == 0) {
        if (bpf_map_delete_elem(&socket_data_args, &id) == 0) {
            __sync_fetch_and_add(&socket_data_args_hash_live, -1);
        }
    }
}

// the receive flags of include/linux/socket.h that sock_data_args_t.recv_flags keeps
#define SOCK_RECV_FLAG_MSG_PEEK 0x2
#define SOCK_RECV_FLAG_MSG_TRUNC 0x20
#define SOCK_RECV_FLAGS_NOT_CONSUMED (SOCK_RECV_FLAG_MSG_PEEK | SOCK_RECV_FLAG_MSG_TRUNC)


// Data ids and calls in flight
//
// Every socket call of an fd takes the next data id of its (tgid, fd) when it enters; the user space
// orders the calls of a connection by it. The calls of an fd can run at once on several threads (Go reads
// and writes a connection from different goroutines), and the id must still be unique: two calls with
// the same id are ordered at random. The kernels the access log supports have no atomic fetch-and-add
// for BPF (BPF_FETCH needs 5.12, and old kernels reject the instruction even where it is never run), only
// an atomic add without a result (BPF_XADD). So the id is added atomically and read back, which is
// unique unless another call added in between: that call is in flight at the same time, which the counter
// of the calls in flight shows. A call that sees no other call in flight takes its id as it read it: a call
// that takes the same id would be in flight while it reads it, unless it entered and returned entirely
// between the add and the read of this one, two instructions apart.
// A call that sees another call in flight checks that the id it read is the result of its own add: it reads
// the id before its add as well, and the id is its own when the two differ by exactly 1. The accesses of one
// call to one location are ordered (per-location coherence, on any CPU), and every add moves the id by
// exactly 1, so a difference of 1 means that no add but its own came between the two reads: the add that made
// the id is its own, and no other call's add makes the same value. A call whose check fails adds again and
// checks again (each failed add is a data id no call takes, as the failed claims made before), so it never
// takes an id it did not make; a call that sees no other call in flight cannot take one either (above). The
// check costs one read; the claims it replaces (an insert into an LRU map that every insert made evict, about
// 1.5 us) were made by about a fifth of the calls of a connection that reads and writes on two threads, while
// the check fails only when two adds land in the same few instructions (tens of times a second at 10 thousand
// requests a second). Outside those races the ids are those the claims gave.
//
// The counter of the calls in flight is also what proves the order of the uploads: a call that sees no
// other call of its fd in flight when it returns (socket_data_call_observe, at the start of the exit)
// knows that every call with a smaller data id has already returned, and uploaded whatever it uploads,
// because a call leaves the counter (socket_data_call_leave) only once its exit is done. The HTTP/1 body
// skip (syscalls/h1.h) and the user space only rely on the order of the uploads of a connection when that
// holds, and the event carries the value (in_flight). A call is counted per direction as well: two calls
// of one direction at once deliver their bytes in an order their returns do not show.
struct socket_data_id_t {
    // the data id of the last call that entered
    __u64 data_id;
    // tells this entry apart from a later one of the key: a call only leaves the entry it entered
    __u64 epoch;
    // the calls between their enter and their exit per direction, the receives (SOCK_DATA_DIRECTION_INGRESS) in the
    // lower 32 bits and the sends in the upper 32 (one word, so a call enters and leaves with one atomic add and
    // the exit reads all three counts with one load). All calls in
    // flight are the sum of the two. A count never goes below zero (a call only leaves the entry it entered, once), so
    // the lower half never borrows from the upper one.
    __u64 flight;
    // 1 once a call of the fd found the connection followed as HTTP/2 (sock_data_args_t.no_flight_mark, set in
    // its leave): the calls that enter from then on are not counted in flight (data_id_epoch 0), their exits look
    // nothing up to leave, and their in_flight is 0 (not known). Only the HTTP/1 paths read the calls in flight
    // (syscalls/h1.h, the user space http1skip tracker), and an fd followed as HTTP/2 stays HTTP/2 until it is
    // closed, which deletes the entry. The data ids are unchanged: every call checks that the id it takes is the
    // result of its own add (socket_data_call_enter), whatever it knows of the others in flight.
    __u64 no_flight;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, __u64);
	__type(value, struct socket_data_id_t);
} socket_data_id_generate_map SEC(".maps");

// the adds a call makes at most when the check of its id fails: each failed one means that another call added at
// the same time, so only that many calls of one fd entering at the same instant could leave a call with an id
// it did not check (it takes the last one it read, as a call took its last unclaimed id before)
#define SOCKET_DATA_ID_RETRIES 64

// what a call of the direction adds to socket_data_id_t.flight while it is in flight
static __always_inline __u64 socket_data_flight_unit(__u8 direction) {
    return direction == SOCK_DATA_DIRECTION_INGRESS ? 1 : (1ULL << 32);
}

static __inline __u64 get_socket_data_id(__u8 from, __u64 id, __u32 fd) {
    __u32 tgid = (__u32)(id >> 32);
    __u64 key = ((__u64)tgid << 32) | fd;
    struct socket_data_id_t *gen = bpf_map_lookup_elem(&socket_data_id_generate_map, &key);
    if (!gen) {
        return 0;
    }
    return gen->data_id;
}

// socket_data_call_enter gives the socket call of the arguments its data id and counts it in flight, in
// its data direction (SOCK_DATA_DIRECTION_*)
static __always_inline void socket_data_call_enter(__u64 id, struct sock_data_args_t *args, __u8 direction) {
    __u32 tgid = (__u32)(id >> 32);
    __u64 key = ((__u64)tgid << 32) | args->fd;
    struct socket_data_id_t *gen = bpf_map_lookup_elem(&socket_data_id_generate_map, &key);
    if (!gen) {
        struct socket_data_id_t init = {};
        init.epoch = bpf_ktime_get_ns();
        bpf_map_update_elem(&socket_data_id_generate_map, &key, &init, BPF_NOEXIST);
        gen = bpf_map_lookup_elem(&socket_data_id_generate_map, &key);
        if (!gen) {
            return;
        }
    }
    // a call of an fd followed as HTTP/2 is not counted in flight (socket_data_id_t.no_flight)
    __u64 counted = *(volatile __u64 *)&gen->no_flight == 0;
    if (counted) {
        __sync_fetch_and_add(&gen->flight, socket_data_flight_unit(direction));
    }
    __u64 before = *(volatile __u64 *)&gen->data_id;
    __sync_fetch_and_add(&gen->data_id, 1);
    __u64 data_id = *(volatile __u64 *)&gen->data_id;
    // take the id only once it is the result of this call's own add: another call may have added in between. Every
    // call checks, not only one that saw another one in flight: the calls of an fd followed as HTTP/2 are not counted
    // (no_flight), so a counted call that entered before the fd was marked may meet the add of one that is not (one
    // compare: the id of a call that met no other add is the same as before).
    // The data ids of an fd are unique and increasing in the order of the adds, but not contiguous: a call that met
    // another one's add between its add and its read adds again, and the id its first add made is taken by no call
    // (a gap under calls that enter at once). The user space never expects the next id: it links the uploads by the
    // previous data id they name (include/socket_data.h); a coalesced HTTP/1 run (syscalls/h1.h) names the range of
    // ids it stands for (data_id_span), which may hold such unused ids.
    if (data_id != before + 1) {
        // a bounded loop, not unrolled (5.3+)
#pragma clang loop unroll(disable)
        for (int i = 0; i < SOCKET_DATA_ID_RETRIES; i++) {
            before = *(volatile __u64 *)&gen->data_id;
            __sync_fetch_and_add(&gen->data_id, 1);
            data_id = *(volatile __u64 *)&gen->data_id;
            if (data_id == before + 1) {
                break;
            }
        }
    }
    args->data_id = data_id;
    args->data_id_epoch = counted ? gen->epoch : 0;
    args->call_direction = direction;
}

// socket_data_call_leave takes the call out of the calls in flight of the entry it entered (only once)
static __always_inline void socket_data_call_leave(__u64 id, struct sock_data_args_t *args) {
    if (args->data_id_epoch == 0) {
        return;
    }
    __u32 tgid = (__u32)(id >> 32);
    __u64 key = ((__u64)tgid << 32) | args->fd;
    struct socket_data_id_t *gen = bpf_map_lookup_elem(&socket_data_id_generate_map, &key);
    if (gen != NULL && gen->epoch == args->data_id_epoch) {
        __sync_fetch_and_add(&gen->flight, 0 - socket_data_flight_unit(args->call_direction));
        // the fd is followed as HTTP/2: its later calls are not counted (socket_data_id_t.no_flight)
        if (args->no_flight_mark != 0 && *(volatile __u64 *)&gen->no_flight == 0) {
            *(volatile __u64 *)&gen->no_flight = 1;
        }
    }
    args->data_id_epoch = 0;
}

// The arguments of the call that enters are written in place: into the entry the thread left in
// socket_data_args, zeroed first, or, for a thread without one, into a per CPU buffer that is inserted once the call
// entered, not built on the stack and copied over the entry (a zeroed stack struct of the size of the entry, then a
// load and a store per word); the entry ends up with the same bytes either way.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sock_data_args_t);
} socket_data_args_new_map SEC(".maps");

// what socket_data_call_begin keeps for socket_data_call_finish: the call the thread's entry still held (active, its
// exit was never seen), which leaves the calls in flight once the new call entered, as it left them before; and
// whether the arguments are the per CPU buffer of a thread that has no entry yet
struct sock_data_stale_t {
    __u64 epoch;
    __u32 fd;
    __u8 direction;
    __u8 fresh;
};

// socket_data_call_begin gives the zeroed arguments the entering call of the thread fills (the fields, then
// socket_data_call_enter, then socket_data_call_finish), NULL when there are none
static __always_inline struct sock_data_args_t *socket_data_call_begin(__u64 *id, struct sock_data_stale_t *stale, __u8 direction) {
    stale->epoch = 0;
    stale->fd = 0;
    stale->direction = 0;
    stale->fresh = 0;
    struct sock_data_args_t *args = NULL;
    // the thread's slot, its entry, a slot it claims, or the per CPU buffer of a new entry (see socket_data_args_slots)
    struct sock_data_args_slot_t *slot = socket_data_args_slot(*id);
    if (slot != NULL && slot->tag == *id) {
        args = &slot->args;
    } else if (socket_data_args_hash_live != 0) {
        args = bpf_map_lookup_elem(&socket_data_args, id);
    }
    if (args == NULL && slot != NULL && slot->tag == 0) {
        __u32 index = (__u32)*id & (SOCK_ARGS_SLOTS - 1);
        if (bpf_map_update_elem(&socket_data_args_slot_owner, &index, id, BPF_NOEXIST) == 0) {
            slot->kind = SOCK_ARGS_SLOT_OWN;
            slot->args.active = 0;
            *(volatile __u64 *)&slot->tag = *id;
            args = &slot->args;
        }
    }
    if (args != NULL) {
        if (args->active != 0) {
            stale->epoch = args->data_id_epoch;
            stale->fd = args->fd;
            stale->direction = args->call_direction;
        }
    } else {
        __u32 kZero = 0;
        args = bpf_map_lookup_elem(&socket_data_args_new_map, &kZero);
        if (args == NULL) {
            return NULL;
        }
        stale->fresh = 1;
    }
    __builtin_memset(args, 0, SOCK_DATA_ARGS_ZERO_LEN);
    return args;
}

// socket_data_call_finish keeps the arguments of the call that entered for its exit: the entry is active from now on;
// the call the entry held before leaves the calls in flight. A new thread's arguments are inserted, and a call whose
// arguments cannot be kept leaves the calls in flight right away: no exit would.
static __always_inline void socket_data_call_finish(__u64 id, struct sock_data_args_t *args, struct sock_data_stale_t *stale,
                                                    __u8 direction) {
    args->active = 1;
    if (stale->fresh != 0) {
        if (bpf_map_update_elem(&socket_data_args, &id, args, 0) != 0) {
            socket_data_call_leave(id, args);
        } else {
            __sync_fetch_and_add(&socket_data_args_hash_live, 1);
        }
    } else if (stale->epoch != 0) {
        __u32 tgid = (__u32)(id >> 32);
        __u64 key = ((__u64)tgid << 32) | stale->fd;
        struct socket_data_id_t *gen = bpf_map_lookup_elem(&socket_data_id_generate_map, &key);
        if (gen != NULL && gen->epoch == stale->epoch) {
            __sync_fetch_and_add(&gen->flight, 0 - socket_data_flight_unit(stale->direction));
        }
    }
}

// socket_data_call_done ends the call of the thread at its exit, once the exit is done with its arguments (got
// with socket_data_args_get, NULL when the thread is in no call): it leaves the calls in flight and its entry
// turns inactive, which the readers see as no entry (the exit deleted it before)
static __always_inline void socket_data_call_done(__u64 id, struct sock_data_args_t *args) {
    if (args != NULL) {
        socket_data_call_leave(id, args);
        args->active = 0;
        // (an exit that worked on the copy of an entry, socket_data_args_exit_get)
        socket_data_args_commit(id, args);
    }
}

// socket_data_call_observe records the calls of the fd in flight as the call returns, at the start of its
// exit (sock_data_args_t.in_flight): any number but 1 means another call may have overlapped it
static __always_inline void socket_data_call_observe(__u64 id, struct sock_data_args_t *args) {
    args->in_flight = 0;
    args->in_flight_direction = 0;
    args->in_flight_other = 0xff;
    if (args->data_id_epoch == 0) {
        return;
    }
    __u32 tgid = (__u32)(id >> 32);
    __u64 key = ((__u64)tgid << 32) | args->fd;
    struct socket_data_id_t *gen = bpf_map_lookup_elem(&socket_data_id_generate_map, &key);
    if (gen == NULL || gen->epoch != args->data_id_epoch) {
        return;
    }
    __u64 flight = *(volatile __u64 *)&gen->flight;
    __u64 ingress = flight & 0xffffffff;
    __u64 egress = flight >> 32;
    __u64 all = ingress + egress;
    __u64 same = args->call_direction == SOCK_DATA_DIRECTION_INGRESS ? ingress : egress;
    __u64 other = args->call_direction == SOCK_DATA_DIRECTION_INGRESS ? egress : ingress;
    // a count above the bound (or below zero) is not a count anymore: unknown
    if (all <= 0xffff) {
        args->in_flight = all;
    }
    if (same <= 0xff) {
        args->in_flight_direction = same;
    }
    if (other < 0xff) {
        args->in_flight_other = other;
    }
}
