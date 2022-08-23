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

package elf

import "debug/dwarf"

type ClassInfo struct {
	name         string
	inheritances []*ClassInheritance
	members      []*dwarf.StructField
}

func (c *ClassInfo) GetInheritanceOffset(name string) int64 {
	for _, i := range c.inheritances {
		if i.name == name {
			return int64(i.offset)
		}
	}
	return -1
}

func (c *ClassInfo) GetMemberOffset(name string) int64 {
	for _, m := range c.members {
		if m.Name == name {
			return m.ByteOffset
		}
	}
	return -1
}

type ClassInheritance struct {
	name   string
	cType  *dwarf.StructType
	offset uint64
}
