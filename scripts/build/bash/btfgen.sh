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

TMPDIR=$1
ARCH=$2
FROM=$3
OUTPUT=$4
BPF_SO_PATTERN="^bpf\_[a-z0-9]+\.o"

echo "btfhub-archive is a big archive project, maybe take some times..."
git clone --depth 1 https://github.com/aquasecurity/btfhub $TMPDIR/btfhub
git clone --depth 1 https://github.com/aquasecurity/btfhub-archive/ $TMPDIR/btfhub-archive/
mv $TMPDIR/btfhub-archive/* $TMPDIR/btfhub/archive/

each_all_bpf_so_file() {
    result=""
    for file in `ls -a $1`
    do
        if [ -d $1"/"$file ]
        then
            if [[ $file != '.' && $file != '..' ]]
            then
                each_all_bpf_so_file $1"/"$file
            fi
        elif [[ "$file" =~ $BPF_SO_PATTERN ]]
        then
          echo "-o $1/$file"
        fi
    done
}

${TMPDIR}/btfhub/tools/btfgen.sh -a ${ARCH} $(each_all_bpf_so_file $FROM)
mkdir -p ${OUTPUT}
cp -r ${TMPDIR}/btfhub/custom-archive/* ${OUTPUT}