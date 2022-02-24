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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"
)

func (c *Client) registerCheckStatus(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timeTicker := time.NewTicker(time.Duration(c.config.CheckPeriod) * time.Second)
	for {
		select {
		case <-timeTicker.C:
			state := c.conn.GetState()
			if state == connectivity.Shutdown || state == connectivity.TransientFailure {
				c.updateStatus(Disconnect)
			} else if state == connectivity.Ready || state == connectivity.Idle {
				c.updateStatus(Connected)
			}
		case <-ctx.Done():
			timeTicker.Stop()
			return
		}
	}
}

func (c *Client) GetConnectionStatus() ConnectionStatus {
	return c.status
}

func (c *Client) RegisterListener() chan<- ConnectionStatus {
	statuses := make(chan ConnectionStatus, 1)
	c.listeners = append(c.listeners, statuses)
	return statuses
}

func (c *Client) reportError(err error) {
	if err == nil {
		return
	}
	fromError, ok := status.FromError(err)
	if ok {
		errCode := fromError.Code()
		if errCode == codes.Unavailable || errCode == codes.PermissionDenied ||
			errCode == codes.Unauthenticated || errCode == codes.ResourceExhausted || errCode == codes.Unknown {
			c.updateStatus(Disconnect)
		}
	}
}

func (c *Client) updateStatus(s ConnectionStatus) {
	if c.status != s {
		c.status = s
		for _, lis := range c.listeners {
			lis <- s
		}
	}
}
