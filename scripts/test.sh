#!/bin/bash

set -eu
set -o pipefail

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

function bootDB {
  db=$1

  if [ "$db" = "postgres" ]; then
    launchDB="(docker-entrypoint.sh postgres &> /var/log/postgres-boot.log) &"
    testConnection="psql -h localhost -U postgres -c '\conninfo' &>/dev/null"
  elif [ "$db" = "mysql" ]  || [ "$db" = "mysql-5.6" ]; then
    launchDB="(MYSQL_ROOT_PASSWORD=password /entrypoint.sh mysqld &> /var/log/mysql-boot.log) &"
    testConnection="echo '\s;' | mysql -h 127.0.0.1 -u root --password='password' &>/dev/null"
  else
    echo "skipping database"
    return 0
  fi

  echo -n "booting $db"
  eval "${launchDB}"
  for _ in $(seq 1 60); do
    set +e
    eval "${testConnection}"
    exitcode=$?
    set -e
    if [ ${exitcode} -eq 0 ]; then
      echo "connection established to $db"
      return 0
    fi
    echo -n "."
    sleep 1
  done
  echo "unable to connect to $db"
  exit 1
}

bootDB ${DB}

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
