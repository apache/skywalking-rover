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

package unwind

import (
	"debug/elf"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/apache/skywalking-rover/pkg/logger"
)

var log = logger.GetLogger("tools", "profiling", "unwind")

// tableCacheLimit is the max count of the cached ELF files
const tableCacheLimit = 256

// tableCacheKey identifies the ELF file by the device and inode, so the same file accessed by
// the different paths(such as /proc/<pid>/root/...) shares the same frame table
type tableCacheKey struct {
	dev, ino uint64
	// the path is only used when the device and inode are not available
	path    string
	size    int64
	modTime time.Time
}

// TableCache caches the parsed frame tables of the ELF files
type TableCache struct {
	arch   *Arch
	lock   sync.Mutex
	tables map[tableCacheKey]*FrameTable
	// needs caches the result of NeedsUnwinding, so the frame table which is not needed could be released
	needs map[tableCacheKey]bool
}

// NewTableCache creates a new cache for the frame tables
func NewTableCache(arch *Arch) *TableCache {
	return &TableCache{
		arch:   arch,
		tables: make(map[tableCacheKey]*FrameTable),
		needs:  make(map[tableCacheKey]bool),
	}
}

func newTableCacheKey(path string) (tableCacheKey, bool) {
	stat, err := os.Stat(path)
	if err != nil {
		return tableCacheKey{}, false
	}
	key := tableCacheKey{size: stat.Size(), modTime: stat.ModTime()}
	if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
		key.dev, key.ino = sys.Dev, sys.Ino
	} else {
		key.path = path
	}
	return key, true
}

// Get the frame table of the ELF file, returns nil when the file has no call frame information
func (c *TableCache) Get(path string) *FrameTable {
	key, ok := newTableCacheKey(path)
	if !ok {
		return nil
	}
	c.lock.Lock()
	table, exist := c.tables[key]
	c.lock.Unlock()
	if exist {
		return table
	}

	table = c.load(path)
	c.lock.Lock()
	defer c.lock.Unlock()
	c.storeTable(key, table)
	return table
}

// NeedsUnwinding checks the ELF file is built without the frame pointer, and has the call frame information
// to unwind it. Only the result is kept, the frame table is cached only when it needs unwinding,
// so checking the processes which keep the frame pointer wouldn't hold their frame tables
func (c *TableCache) NeedsUnwinding(path string) bool {
	key, ok := newTableCacheKey(path)
	if !ok {
		return false
	}
	c.lock.Lock()
	needs, exist := c.needs[key]
	table, tableExist := c.tables[key]
	c.lock.Unlock()
	if exist {
		return needs
	}

	if !tableExist {
		table = c.load(path)
	}
	needs = table != nil && table.HasCallFrameInformation() && !table.KeepsFramePointer()

	c.lock.Lock()
	defer c.lock.Unlock()
	if len(c.needs) >= tableCacheLimit {
		c.needs = make(map[tableCacheKey]bool)
	}
	c.needs[key] = needs
	if needs && !tableExist {
		c.storeTable(key, table)
	}
	return needs
}

func (c *TableCache) load(path string) *FrameTable {
	table, err := LoadFrameTable(c.arch, path)
	if err != nil {
		log.Debugf("could not load the call frame information from %s: %v", path, err)
	}
	return table
}

// storeTable must be called with the lock held
func (c *TableCache) storeTable(key tableCacheKey, table *FrameTable) {
	if len(c.tables) >= tableCacheLimit {
		c.tables = make(map[tableCacheKey]*FrameTable)
	}
	c.tables[key] = table
}

// LoadFrameTable reads the .eh_frame section from the ELF file
func LoadFrameTable(arch *Arch, path string) (*FrameTable, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	section := file.Section(".eh_frame")
	if section == nil || section.Type == elf.SHT_NOBITS {
		return nil, fmt.Errorf("no .eh_frame section")
	}
	data, err := section.Data()
	if err != nil {
		return nil, err
	}
	table, err := ParseEHFrame(arch, data, section.Addr)
	if err != nil {
		return nil, err
	}
	for _, sec := range file.Sections {
		if sec.Flags&elf.SHF_EXECINSTR != 0 && sec.Type != elf.SHT_NOBITS {
			table.codeSize += sec.Size
		}
	}
	return table, nil
}
