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
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

var (
	openSSLVersionRegex = regexp.MustCompile(`^OpenSSL\s+(?P<Major>\d)\.(?P<Minor>\d)\.(?P<Fix>\d+)\w?`)
)

type OpenSSLSymbolAddresses struct {
	BIOReadOffset  uint32
	BIOWriteOffset uint32
	FDOffset       uint32
	RoleOffset     uint32
}

func (r *Register) OpenSSL(symbolAddrMap *ebpf.Map, sslWrite, sslWriteRet, sslRead, sslReadRet *ebpf.Program) {
	r.addHandler("OpenSSL", func() (bool, error) {
		var libcryptoName, libsslName = "libcrypto.so", "libssl.so"
		var libcryptoPath, libsslPath string
		modules, err := r.findModules(libcryptoName, libsslName)
		if err != nil {
			return false, err
		}
		if len(modules) == 0 {
			return false, nil
		}
		if libcrypto := modules[libcryptoName]; libcrypto != nil {
			libcryptoPath = libcrypto.Path
		}
		if libssl := modules[libsslName]; libssl != nil {
			libsslPath = libssl.Path
		}
		if libcryptoPath == "" || libsslPath == "" {
			return false, fmt.Errorf("the OpenSSL library not complete, libcrypto: %s, libssl: %s", libcryptoPath, libsslPath)
		}

		addresses, err := r.buildOpenSSLSymAddrConfig(libcryptoPath)
		if err != nil {
			return false, err
		}

		if err := symbolAddrMap.Put(uint32(r.pid), addresses); err != nil {
			return false, err
		}

		libSSLLinker := r.linker.OpenUProbeExeFile(libsslPath)
		libSSLLinker.AddLink("SSL_write", sslWrite, sslWriteRet)
		libSSLLinker.AddLink("SSL_read", sslRead, sslReadRet)
		if err := r.linker.HasError(); err != nil {
			return false, err
		}
		return true, nil
	})
}

func (r *Register) buildOpenSSLSymAddrConfig(libcryptoPath string) (*OpenSSLSymbolAddresses, error) {
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
		minor := submatch[2]
		fix := submatch[3]

		log.Debugf("found the libcrypto.so version: %s.%s.%s", major, minor, fix)
		conf := &OpenSSLSymbolAddresses{}

		// must be number, already validate in the regex
		majorVal, _ := strconv.Atoi(major)
		minorVal, _ := strconv.Atoi(minor)
		fixVal, _ := strconv.Atoi(fix)

		// max support version is 3.0.x
		if majorVal > 3 || (majorVal == 3 && minorVal > 0) {
			return nil, fmt.Errorf("the version of the libcrypto is not support: %s.%s.%s", major, minor, fix)
		}

		// bio offset
		// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/ssl/ssl.h#L1093-L1111
		// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/ssl/ssl_local.h#L1068-L1083
		// https://github.com/openssl/openssl/blob/openssl-3.0.7/ssl/ssl_local.h#L1212-L1227
		conf.BIOReadOffset = 16
		conf.BIOWriteOffset = 24
		// fd offset
		if majorVal == 3 && minorVal == 0 {
			// 3.0.x
			// https://github.com/openssl/openssl/blob/openssl-3.0.7/crypto/bio/bio_local.h#L115-L128
			// OPENSSL_NO_DEPRECATED_3_0 is not defined by default unless the user pass the specific build option
			conf.FDOffset = 56
			// https://github.com/openssl/openssl/blob/openssl-3.0.7/ssl/ssl_local.h#L1212-L1245
			conf.RoleOffset = 56
		} else if (minorVal == 0) || (minorVal == 1 && fixVal == 0) {
			// 1.0.x || 1.1.0
			// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/crypto/bio/bio.h#L297-L306
			conf.FDOffset = 40
			// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/ssl/ssl.h#L1093-L1138
			conf.RoleOffset = 72
		} else {
			// 1.1.1
			// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h#L115-L125
			conf.FDOffset = 48
			// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/ssl/ssl_local.h#L1068-L1101
			conf.RoleOffset = 56
		}
		log.Debugf("the lobcrypto.so library symbol verson config, version: %s.%s.%s, bio offset: %d",
			major, minor, fix, conf.FDOffset)
		return conf, nil
	}
	return nil, fmt.Errorf("could not fount the version of the libcrypto.so")
}
