#!/bin/bash
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

HOST=${1:-localhost}
PASSWORD=test
TARGET_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR=$2

root_key="$TARGET_DIR/root_${HOST}.key"
root_csr="$TARGET_DIR/root_${HOST}.csr"
root_crt="$TARGET_DIR/root_${HOST}.crt"

key="$TARGET_DIR/${HOST}.key"
csr="$TARGET_DIR/${HOST}.csr"
crt="$TARGET_DIR/${HOST}.crt"

CountryName=CN
StateORProvinceName=beijing
LocalityName=beijing
OrgName=sky
OrgUnitName=sky
CommonName=$HOST
Email=xx@gmail.com
ChallengePwd=.
OptionalComName=.

# root ca
openssl genrsa -des3 -out $root_key -passout pass:$PASSWORD 2048

openssl req -new -key $root_key -out $root_csr -passin pass:$PASSWORD -passout pass:$PASSWORD <<EOF
${CountryName}
${StateORProvinceName}
${LocalityName}
${OrgName}
${OrgUnitName}
${CommonName}
${Email}
${ChallengePwd}
${OptionalComName}
EOF

openssl x509 -req -days 365 -sha256 -signkey $root_key -in $root_csr -out $root_crt -passin pass:$PASSWORD -extfile <(printf "subjectAltName=DNS:$HOST,DNS:localhost,IP:127.0.0.1")

openssl genrsa -des3 -out $key -passout pass:$PASSWORD 2048

openssl rsa -in $key -out $key -passin pass:$PASSWORD

openssl req -new -key $key -out $csr <<EOF
${CountryName}
${StateORProvinceName}
${LocalityName}
${OrgName}
${OrgUnitName}
${CommonName}
${Email}
${ChallengePwd}
${OptionalComName}
EOF

openssl x509 -req -days 365 -sha256 -CA $root_crt -CAkey $root_key -CAcreateserial -in $csr -out $crt -passin pass:$PASSWORD -extfile <(printf "subjectAltName=DNS:$HOST,DNS:localhost,IP:127.0.0.1")

# adding trusted root certificates to the server
sudo cp $root_crt $crt /usr/local/share/ca-certificates/
sudo update-ca-certificates