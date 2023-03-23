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

package ssl

import (
	"os/exec"
	"testing"

	gomonkey "github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
)

func TestBuildSSLSymAddrConfig(t *testing.T) {
	mockOutput := func(out string) *exec.Cmd {
		return exec.Command("echo", out)
	}
	register := NewSSLRegister(0, nil)

	result := `%s:%d: OpenSSL internal error: %s
OpenSSL 1.0.2o  31 Mar 2020
OpenSSL X9.42 DH method`
	patches := gomonkey.ApplyFuncReturn(exec.Command, mockOutput(result))
	t.Cleanup(func() {
		patches.Reset()
	})

	conf, err := register.buildOpenSSLSymAddrConfig("/test")
	assert.Nil(t, err)
	assert.Equal(t, uint32(16), conf.BIOReadOffset)
	assert.Equal(t, uint32(24), conf.BIOWriteOffset)
	assert.Equal(t, uint32(40), conf.FDOffset)

	patches.Reset()
	result = `%s:%d: OpenSSL internal error: %s
OpenSSL 1.1.1f  31 Mar 2020
OpenSSL X9.42 DH method`
	patches = gomonkey.ApplyFuncReturn(exec.Command, mockOutput(result))
	conf, err = register.buildOpenSSLSymAddrConfig("/test")
	assert.Nil(t, err)
	assert.Equal(t, uint32(16), conf.BIOReadOffset)
	assert.Equal(t, uint32(24), conf.BIOWriteOffset)
	assert.Equal(t, uint32(48), conf.FDOffset)

	// should same with 1.1.1, which from the NodeJS build-in version of OpenSSL
	patches.Reset()
	result = `OpenSSL 1.1.1q+quic  5 Jul 2022`
	patches = gomonkey.ApplyFuncReturn(exec.Command, mockOutput(result))
	conf, err = register.buildOpenSSLSymAddrConfig("/test")
	assert.Nil(t, err)
	assert.Equal(t, uint32(16), conf.BIOReadOffset)
	assert.Equal(t, uint32(24), conf.BIOWriteOffset)
	assert.Equal(t, uint32(48), conf.FDOffset)

	patches.Reset()
	result = `%s:%d: OpenSSL internal error: %s
OpenSSL 3.0.3 3 May 2022
OpenSSL RSA method`
	patches = gomonkey.ApplyFuncReturn(exec.Command, mockOutput(result))
	conf, err = register.buildOpenSSLSymAddrConfig("/test")
	assert.Nil(t, err)
	assert.Equal(t, uint32(16), conf.BIOReadOffset)
	assert.Equal(t, uint32(24), conf.BIOWriteOffset)
	assert.Equal(t, uint32(56), conf.FDOffset)
}
