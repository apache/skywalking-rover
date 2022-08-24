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

const https = require('https');
const fs = require('fs');

const options = {
    key: fs.readFileSync('/ssl_data/service.key'),
    cert: fs.readFileSync('/ssl_data/service.crt')
};

https.createServer(options, function (req, res) {
    if (req.url == '/provider') {
        res.writeHead(200, {"Content-Type": "text/html"});
        res.end('provider');
        return;
    }

    const sendReq = https.request({
        hostname: 'proxy',
        port: 443,
        path: '/provider',
        method: 'GET'
    }, proxyResp => {
        proxyResp.on('data', d => {
            res.writeHead(200, {"Content-Type": "text/html"});
            res.end('success');
        })
    })
    sendReq.on('error', error => {
        res.writeHead(200, {"Content-Type": "text/html"});
        console.log(error)
        res.end('error');
    })
    sendReq.end()
}).listen(10443);

console.log("https server started!")
