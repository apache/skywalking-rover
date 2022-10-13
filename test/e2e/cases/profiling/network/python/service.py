# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import time
import requests
from contextlib import contextmanager
from socketserver import ThreadingMixIn

@contextmanager
def disable_ssl_warnings():
    import warnings
    import urllib3

    with warnings.catch_warnings():
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        yield None

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/consumer':
            try:
                r = requests.get("https://proxy/provider", verify=False)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(r.content)
            except:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'error')
            return

        time.sleep(2)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'service provider')
        return

class ThreadingSimpleServer(ThreadingMixIn,HTTPServer):
    pass

httpd = ThreadingSimpleServer(('0.0.0.0', 10443), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket,
        keyfile="/ssl_data/service.key",
        certfile='/ssl_data/service.crt', server_side=True)
httpd.serve_forever()