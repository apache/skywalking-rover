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

package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Client struct {
	config *Config

	conn      *grpc.ClientConn
	status    ConnectionStatus
	listeners []chan<- ConnectionStatus
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewClient(config *Config) *Client {
	return &Client{config: config}
}

// Start the backend client and connect to server
func (c *Client) Start(parent context.Context) error {
	c.ctx, c.cancel = context.WithCancel(parent)
	// build config
	options, err := c.buildConfig(c.config)
	if err != nil {
		return err
	}

	// build connection
	addr := c.config.Addr
	conn, err := grpc.Dial(addr, options...)
	if err != nil {
		return err
	}
	c.conn = conn

	// register status change
	go c.registerCheckStatus(c.ctx)
	return nil
}

func (c *Client) GetConnection() grpc.ClientConnInterface {
	return c.conn
}

func (c *Client) Stop() error {
	c.cancel()
	return c.conn.Close()
}

func (c *Client) buildConfig(conf *Config) ([]grpc.DialOption, error) {
	options := make([]grpc.DialOption, 0)

	if conf.EnableTLS {
		t, err := configTLS(conf)
		if err != nil {
			return nil, err
		}
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(t)))
	} else {
		options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if conf.Authentication != "" {
		authHeader := metadata.New(map[string]string{"Authentication": conf.Authentication})
		options = append(options,
			grpc.WithStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
				method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
				ctx = metadata.NewOutgoingContext(ctx, authHeader)
				stream, err := streamer(ctx, desc, cc, method, opts...)
				if err != nil {
					c.reportError(err)
				}
				return stream, err
			}),
			grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply interface{},
				cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
				ctx = metadata.NewOutgoingContext(ctx, authHeader)
				err := invoker(ctx, method, req, reply, cc, opts...)
				if err != nil {
					c.reportError(err)
				}
				return err
			}))
	}

	return options, nil
}

// configTLS loads and parse the TLS configs.
func configTLS(conf *Config) (tc *tls.Config, tlsErr error) {
	if err := checkTLSFile(conf.CaPemPath); err != nil {
		return nil, err
	}
	tlsConfig := new(tls.Config)
	tlsConfig.Renegotiation = tls.RenegotiateNever
	tlsConfig.InsecureSkipVerify = conf.InsecureSkipVerify
	caPem, err := os.ReadFile(conf.CaPemPath)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPem) {
		return nil, fmt.Errorf("failed to append certificates")
	}
	tlsConfig.RootCAs = certPool

	if conf.ClientKeyPath != "" && conf.ClientPemPath != "" {
		if err := checkTLSFile(conf.ClientKeyPath); err != nil {
			return nil, err
		}
		if err := checkTLSFile(conf.ClientPemPath); err != nil {
			return nil, err
		}
		clientPem, err := tls.LoadX509KeyPair(conf.ClientPemPath, conf.ClientKeyPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{clientPem}
	}
	return tlsConfig, nil
}

// checkTLSFile checks the TLS files.
func checkTLSFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	if stat.Size() == 0 {
		return fmt.Errorf("the TLS file is illegal: %s", path)
	}
	return nil
}
