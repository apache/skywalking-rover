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

package offsets

import (
	"github.com/apache/skywalking-rover/pkg/tools/elf"

	"github.com/hashicorp/go-multierror"
)

var nodeTLSWrap = "TLSWrap"
var nodeTLSStreamListener = "StreamListener"
var nodeTLSStreamBase = "StreamBase"
var nodeTLSStreamResource = "StreamResource"
var nodeTLSStreamField = "stream_"
var nodeTLSLibuvStreamWrap = "LibuvStreamWrap"
var nodeTLSUVStream = "uv_stream_s"
var nodeTLSIOWatcher = "io_watcher"
var nodeTLSUVIO = "uv__io_s"
var nodeTLSFD = "fd"

type NodeTLSAddrInBPF struct {
	TLSWrapStreamListenerOffset     uint32
	StreamListenerStreamOffset      uint32
	StreamBaseStreamResourceOffset  uint32
	LibuvStreamWrapStreamBaseOffset uint32
	LibuvStreamWrapStreamOffset     uint32
	UVStreamSIOWatcherOffset        uint32
	UVIOSFDOffset                   uint32
}

func GenerateNodeTLSAddresses(path string) (*NodeTLSAddrInBPF, error) {
	file, err := elf.NewFile(path)
	if err != nil {
		return nil, err
	}
	reader, err := file.NewDwarfReader(nodeTLSWrap, nodeTLSStreamListener, nodeTLSStreamBase, nodeTLSLibuvStreamWrap,
		nodeTLSLibuvStreamWrap, nodeTLSUVStream, nodeTLSUVIO)
	if err != nil {
		return nil, err
	}

	result := &NodeTLSAddrInBPF{}
	err = findOrError(err, &result.TLSWrapStreamListenerOffset, reader.GetClassParentOffset, nodeTLSWrap, nodeTLSStreamListener)
	err = findOrError(err, &result.StreamListenerStreamOffset, reader.GetClassMemberOffset, nodeTLSStreamListener, nodeTLSStreamField)
	err = findOrError(err, &result.StreamBaseStreamResourceOffset, reader.GetClassParentOffset, nodeTLSStreamBase, nodeTLSStreamResource)
	err = findOrError(err, &result.LibuvStreamWrapStreamBaseOffset, reader.GetClassParentOffset, nodeTLSLibuvStreamWrap, nodeTLSStreamBase)
	err = findOrError(err, &result.LibuvStreamWrapStreamOffset, reader.GetClassMemberOffset, nodeTLSLibuvStreamWrap, nodeTLSStreamField)
	err = findOrError(err, &result.UVStreamSIOWatcherOffset, reader.GetStructMemberOffset, nodeTLSUVStream, nodeTLSIOWatcher)
	err = findOrError(err, &result.UVIOSFDOffset, reader.GetStructMemberOffset, nodeTLSUVIO, nodeTLSFD)

	return result, err
}

func findOrError(err error, target *uint32, f func(name1, name2 string) (uint64, error), val1, val2 string) error {
	d, e := f(val1, val2)
	if e != nil {
		return multierror.Append(err, e)
	}
	*target = uint32(d)
	return err
}
