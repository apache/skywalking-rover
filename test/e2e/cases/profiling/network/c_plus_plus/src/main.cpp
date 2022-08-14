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

#include <httplib.h>
#include <iostream>

#define SERVER_CERT_FILE "/ssl_data/service.crt"
#define SERVER_PRIVATE_KEY_FILE "/ssl_data/service.key"

using namespace httplib;

int main(void) {
    SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
    if (!svr.is_valid()) {
        printf("server has an error...\n");
        return -1;
    }

    svr.Get("/consumer", [](const Request &, Response &res) {
        httplib::SSLClient cli("proxy", 443);

        if (auto httpRes = cli.Get("/provider")) {
            if (httpRes->status == 200) {
                res.set_content(httpRes->body, "text/plain");
                return;
            }
        } else {
            std::cout << "error code: " << httpRes.error() << std::endl;
            auto result = cli.get_openssl_verify_result();
            if (result) {
                std::cout << "verify error: " << X509_verify_cert_error_string(result) << std::endl;
            }
        }
        res.set_content("failure", "text/plain");
    });

    svr.Get("/provider", [](const Request &, Response &res) {
        res.set_content("service provider", "text/plain");
    });

    svr.listen("0.0.0.0", 10443);
    return 0;
}
