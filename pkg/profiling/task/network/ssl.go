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

package network

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/apache/skywalking-rover/pkg/tools/profiling"

	"github.com/apache/skywalking-rover/pkg/tools"

	"github.com/apache/skywalking-rover/pkg/tools/path"
)

var openSSLVersionRegex = regexp.MustCompile(`^OpenSSL\s+(?P<Major>\d)\.(?P<Minor>\d)\.(?P<Fix>\d+)\w+`)

type OpenSSLFdSymAddrConfigInBPF struct {
	BIOReadOffset  uint32
	BIOWriteOffset uint32
	FDOffset       uint32
}

func addSSLProcess(pid int, bpf *bpfObjects, linker *Linker) error {
	modules, err := tools.ProcessModules(int32(pid))
	if err != nil {
		return fmt.Errorf("read process modules error: %d, error: %v", pid, err)
	}

	// openssl process
	if err1 := processOpenSSLProcess(pid, bpf, linker, modules); err1 != nil {
		return err1
	}

	return nil
}

func processOpenSSLProcess(pid int, bpf *bpfObjects, linker *Linker, modules []*profiling.Module) error {
	var libcryptoName, libsslName = "libcrypto.so", "libssl.so"
	var libcryptoPath, libsslPath string
	processModules, err := findProcessModules(modules, libcryptoName, libsslName)
	if err != nil {
		return err
	}
	// the openssl not exists, so ignore
	if len(processModules) == 0 {
		return nil
	}
	if libcrypto := processModules[libcryptoName]; libcrypto != nil {
		libcryptoPath = libcrypto.Path
	}
	if libssl := processModules[libsslName]; libssl != nil {
		libsslPath = libssl.Path
	}
	if libcryptoPath == "" || libsslPath == "" {
		return fmt.Errorf("the OpenSSL library not complete, libcrypto: %s, libssl: %s", libcryptoPath, libsslPath)
	}

	// build the symbol address config and write to the bpf
	conf, err := buildSSLSymAddrConfig(libcryptoPath)
	if err != nil {
		return err
	}
	if err := bpf.OpensslFdSymaddrFinder.Put(uint32(pid), conf); err != nil {
		return err
	}

	// attach the linker
	libSSLLinker := linker.OpenUProbeExeFile(libsslPath)
	libSSLLinker.AddLink("SSL_write", bpf.OpensslWrite, bpf.OpensslWriteRet, pid)
	libSSLLinker.AddLink("SSL_read", bpf.OpensslRead, bpf.OpensslReadRet, pid)
	return linker.HasError()
}

func findProcessModules(modules []*profiling.Module, moduleNames ...string) (map[string]*profiling.Module, error) {
	result := make(map[string]*profiling.Module)
	for _, mod := range modules {
		for _, modName := range moduleNames {
			if strings.Contains(mod.Name, modName) {
				if !path.Exists(mod.Path) {
					return nil, fmt.Errorf("the module path not exists, path: %s", mod.Path)
				}
				result[modName] = mod
			}
		}
	}
	return result, nil
}

func buildSSLSymAddrConfig(libcryptoPath string) (*OpenSSLFdSymAddrConfigInBPF, error) {
	// using "strings" command to query the symbol in the libcrypto library
	result, err := exec.Command("strings", libcryptoPath).Output()
	if err != nil {
		return nil, err
	}
	for _, p := range strings.Split(string(result), "\n") {
		submatch := openSSLVersionRegex.FindStringSubmatch(p)
		if len(submatch) != 4 {
			continue
		}
		major := submatch[1]
		mijor := submatch[2]
		fix := submatch[3]

		log.Debugf("found the libcrypto.so version: %s.%s.%s", major, mijor, fix)
		conf := &OpenSSLFdSymAddrConfigInBPF{}

		// must be number, already validate in the regex
		mijorVal, _ := strconv.Atoi(mijor)
		fixVal, _ := strconv.Atoi(fix)

		// max support version is 1.1.1
		if mijorVal > 1 || fixVal > 1 {
			return nil, fmt.Errorf("the fix version of the libcrypto is not support: %s.%s.%s", major, mijor, fix)
		}

		// bio offset
		// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/ssl/ssl.h#L1093-L1111
		// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/ssl/ssl_local.h#L1068-L1083
		conf.BIOReadOffset = 16
		conf.BIOWriteOffset = 24
		// fd offset
		if (mijorVal == 0) || (mijorVal == 1 && fixVal == 0) {
			// 1.0.x || 1.1.0
			// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/crypto/bio/bio.h#L297-L306
			conf.FDOffset = 40
		} else {
			// 1.1.1
			// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h#L115-L125
			conf.FDOffset = 48
		}
		log.Debugf("the lobcrypto.so library symbol verson config, version: %s.%s.%s, bio offset: %d",
			major, mijor, fix, conf.FDOffset)
		return conf, nil
	}
	return nil, fmt.Errorf("could not fount the version of the libcrypto.so")
}
