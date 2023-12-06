#!/bin/bash

set -eu
set -o pipefail

# shellcheck disable=SC2068
# Double-quoting array expansion here causes ginkgo to fail
args=${@} 
# run in serial
go run github.com/onsi/ginkgo/v2/ginkgo $args --nodes=1 ./integration
