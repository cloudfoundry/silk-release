#!/bin/bash

specificied_package="${1}"

set -e -u

go version # so we see the version tested in CI

SCRIPT_PATH="$(cd "$(dirname "${0}")" && pwd)"
. "${SCRIPT_PATH}/start-db-helper"

cd "${SCRIPT_PATH}/.."

DB="${DB:-"notset"}"

## Setting to other than 1 node will break cni-wrapper-plugin/integration
serial_nodes=1

declare -a serial_packages=(
    "src/code.cloudfoundry.org/cni-wrapper-plugin/integration"
    "src/code.cloudfoundry.org/silk-daemon-bootstrap/integration"
    "src/code.cloudfoundry.org/silk-daemon-shutdown/integration"
    "src/code.cloudfoundry.org/silk/cni/integration"
    "src/code.cloudfoundry.org/vxlan-policy-agent/integration/linux"
    )

declare -a windows_packages=(
    "src/code.cloudfoundry.org/vxlan-policy-agent/integration/windows"
    )

declare -a ignored_packages

# gather ignored packages from exclude_packages
for pkg in $(echo "${exclude_packages:-""}" | jq -r .[]); do
  ignored_packages+=("${pkg}")
done

# gather more ignored packages because they are windows code
for pkg in "${windows_packages[@]}"; do
  ignored_packages+=("${pkg}")
done

containsElement() {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

test_package() {
  local package=$1
  if [ ! -d "${package}" ]; then
    return 0
  fi
  shift
  pushd "${package}" &>/dev/null
  pwd
  go run github.com/onsi/ginkgo/v2/ginkgo --race -randomize-all -randomize-suites -fail-fast \
      -ldflags="extldflags=-WL,--allow-multiple-definition" \
       "${@}";
  rc=$?
  popd &>/dev/null
  return "${rc}"
}

bootDB "${DB}"

declare -a packages
if [[ -n "${include_only:-""}" ]]; then
  mapfile -t packages < <(echo "${include_only}" | jq -r .[])
else
  mapfile -t packages < <(find src -type f -name '*_test.go' -print0 | xargs -0 -L1 -I{} dirname {} | sort -u)
fi

# filter out serial_packages from packages
for i in "${serial_packages[@]}"; do
  packages=("${packages[@]//*$i*}")
done

# filter out explicitly ignored packages
for i in "${ignored_packages[@]}"; do
  packages=("${packages[@]//*$i*}")
  serial_packages=("${serial_packages[@]//*$i*}")
done

if [[ -z "${specificied_package}" ]]; then
  echo "testing packages: " "${packages[@]}"
  for dir in "${packages[@]}"; do
    test_package "${dir}" -p
  done
  echo "testing serial packages: " "${serial_packages[@]}"
  for dir in "${serial_packages[@]}"; do
    test_package "${dir}" --nodes "${serial_nodes}"
  done
else
  specificied_package="${specificied_package#./}"
  if containsElement "${specificied_package}" "${serial_packages[@]}"; then
    echo "testing serial package ${specificied_package}"
    test_package "${specificied_package}" --nodes "${serial_nodes}"
  else
    echo "testing package ${specificied_package}"
    test_package "${specificied_package}" -p
  fi
fi
