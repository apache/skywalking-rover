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

#include "api.h"

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)			\
    __u8 i = 0; \
	for (pos = list_entry(_((head)->next), typeof(*pos), member),	\
		n = list_entry(_(pos->member.next), typeof(*pos), member);	\
	     &pos->member != (head) && i < 255;					\
	     pos = n, n = list_entry(_(n->member.next), typeof(*n), member), i++)

// use for for-each the list without for loop(lower linux kernel)
// use list_for_each_entry_init at first, and use list_for_each_entry_data multiples for the loop
#define list_for_each_entry_init() \
    bool list_is_first = true; \
    bool list_should_enter = false;

#define list_for_each_entry_data(pos, n, head, member) \
    if (list_is_first) {                                              \
        list_should_enter = true;                                     \
        list_is_first = false;                                        \
        pos = list_entry(_((head)->next), typeof(*pos), member);      \
        n = list_entry(_(pos->member.next), typeof(*pos), member);    \
    } else if (list_should_enter) {                                   \
        pos = n;                                                      \
        n = list_entry(_(n->member.next), typeof(*n), member);        \
        list_should_enter = &pos->member != (head);                   \
    } \
    if (list_should_enter)

// Customized BPF List implementation
struct bpf_list_head {
    void *data;
	struct bpf_list_head *next;
};

static inline struct bpf_list_head init_bpf_list_head() {
    struct bpf_list_head head = {};
    head.data = NULL;
    head.next = NULL;
    return head;
}

static inline struct bpf_list_head append_bpf_list_head(struct bpf_list_head* head, void *data) {
    struct bpf_list_head new_head = init_bpf_list_head();
    new_head.data = data;
    new_head.next = head;
    return new_head;
}

static inline int bpf_list_empty(struct bpf_list_head *head) {
	return head->next == NULL;
}

#define bpf_list_for_each_init()			\
    bool bpf_list_is_first = true;          \
    struct bpf_list_head *current_node = NULL;

#define bpf_list_for_each_foreach(pos, head)			\
    if (bpf_list_is_first) {                                \
        current_node = head;                            \
        pos = head->data;\
    } else if (current_node != NULL) {              \
        current_node = current_node->next;                \
        if (current_node != NULL) {\
            pos = current_node->data; \
        }\
    }                       \
    if (current_node != NULL && current_node->next != NULL)