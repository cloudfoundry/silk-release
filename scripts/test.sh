#!/bin/bash

set -eu
set -o pipefail

# In the cf-networking-and-silk-pr.yml pipeline, we need to run db-unit tests for cf-networking, but
# concourse doesn't have a way of conditionally adding jobs, so it will end up running db-unit tests
# against silk, which doesn't do anything other than run unit tests again, so we skip it here.
if [[ -n "${DB:-""}" ]]; then
  echo "No DB specific silk tests have been defined. Skipping this step."
  exit 0
fi

cd $(dirname $0)/..

declare -a serial_packages=(
    "src/code.cloudfoundry.org/cni-wrapper-plugin/integration"
    "src/code.cloudfoundry.org/vxlan-policy-agent/integration/linux"
    "src/code.cloudfoundry.org/silk-daemon-shutdown/integration"
    "src/code.cloudfoundry.org/silk-daemon-bootstrap/integration"
    )

declare -a windows_packages=(
    "src/code.cloudfoundry.org/vxlan-policy-agent/integration/windows"
    )

# get all git submodule paths | print only the path without the extra info | cut the "package root" for go | deduplicate
declare -a git_modules=($(git config --file .gitmodules --get-regexp path | awk '{ print $2 }' | cut -d'/' -f1,2 | sort -u))

declare -a packages=($(find src -type f -name "*_test.go" | xargs -L 1 -I{} dirname {} | sort -u))


# filter out serial_packages from packages
for i in "${serial_packages[@]}"; do
  packages=(${packages[@]//*$i*})
done

# filter out windows_packages from packages
for i in "${windows_packages[@]}"; do
  packages=(${packages[@]//*$i*})
done

install_ginkgo() {
  if ! [ $(type -P "ginkgo") ]; then
    go install -mod=mod github.com/onsi/ginkgo/ginkgo@v1
    go get github.com/onsi/gomega/...
  fi
}
install_ginkgo

if [ "${1:-""}" = "" ]; then
  for dir in "${packages[@]}"; do
    pushd "$dir"
      ginkgo -p --race -randomizeAllSpecs -randomizeSuites \
        -ldflags="-extldflags=-Wl,--allow-multiple-definition" \
        ${@:2}
    popd
  done
  for dir in "${serial_packages[@]}"; do
    pushd "$dir"
      ginkgo --race -randomizeAllSpecs -randomizeSuites -failFast \
        -ldflags="-extldflags=-Wl,--allow-multiple-definition" \
        ${@:2}
    popd
  done
else
  dir="${@: -1}"
  dir="${dir#./}"
  for package in "${serial_packages[@]}"; do
    if [[ "${dir##$package}" != "${dir}" ]]; then
      ginkgo --race -randomizeAllSpecs -randomizeSuites -failFast \
        -ldflags="-extldflags=-Wl,--allow-multiple-definition" \
        "${@}"
      exit $?
    fi
  done
  ginkgo -p --race -randomizeAllSpecs -randomizeSuites -failFast -skipPackage windows \
    -ldflags="-extldflags=-Wl,--allow-multiple-definition" \
    "${@}"
fi
