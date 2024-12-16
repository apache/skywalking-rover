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

package bpf

import (
	"github.com/hashicorp/go-multierror"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
// nolint
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf $REPO_ROOT/bpf/accesslog/accesslog.c -- -I$REPO_ROOT/bpf/include

type Loader struct {
	*btf.Linker
	*bpfObjects
}

func NewLoader() (*Loader, error) {
	objs := bpfObjects{}
	if err := btf.LoadBPFAndAssign(loadBpf, &objs); err != nil {
		return nil, err
	}

	return &Loader{
		bpfObjects: &objs,
		Linker:     btf.NewLinker(),
	}, nil
}

func (l *Loader) Close() error {
	var err error
	if e := l.bpfObjects.Close(); e != nil {
		err = multierror.Append(err, e)
	}
	if e := l.Linker.Close(); e != nil {
		err = multierror.Append(err, e)
	}
	return err
}
