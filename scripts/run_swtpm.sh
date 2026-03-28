#!/bin/bash

mkdir -p /tmp/myswtpm
swtpm socket --tpmstate dir=/tmp/myswtpm --tpm2 \
    --ctrl type=unixio,path=/tmp/myswtpm/swtpm.sock.ctrl \
    --server type=unixio,path=/tmp/myswtpm/swtpm.sock \
    --flags not-need-init
