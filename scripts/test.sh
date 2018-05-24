#!/bin/bash

set -eu
set -o pipefail

cd $(dirname $0)/..
export GOPATH=$PWD

function bootDB {
  db=$1

  if [ "$db" = "postgres" ]; then
    launchDB="(/docker-entrypoint.sh postgres &> /var/log/postgres-boot.log) &"
    testConnection="psql -h localhost -U postgres -c '\conninfo' &>/dev/null"
  elif [ "$db" = "mysql" ]  || [ "$db" = "mysql-5.6" ]; then
    launchDB="(MYSQL_ROOT_PASSWORD=password /entrypoint.sh mysqld &> /var/log/mysql-boot.log) &"
    testConnection="echo '\s;' | mysql -h 127.0.0.1 -u root --password='password' &>/dev/null"
  else
    echo "skipping database"
    return 0
  fi

  echo -n "booting $db"
  eval "$launchDB"
  trycount=0
  for i in `seq 1 30`; do
    set +e
    eval "$testConnection"
    exitcode=$?
    set -e
    if [ $exitcode -eq 0 ]; then
      echo "connection established to $db"
      return 0
    fi
    echo -n "."
    sleep 1
  done
  echo "unable to connect to $db"
  exit 1
}

# go install ./vendor/github.com/onsi/ginkgo/ginkgo

bootDB $DB

declare -a packages=(
   "src/iptables-logger"
   "src/lib"
   "src/netmon"
   )

 declare -a serial_packages=(
   "src/cni-teardown"
   "src/cni-wrapper-plugin"
   "src/vxlan-policy-agent"
   "src/silk-daemon-shutdown"
   "src/silk-daemon-bootstrap"
   )

# ginkgo -r -p --race -randomizeAllSpecs -randomizeSuites \
#   -ldflags="-extldflags=-Wl,--allow-multiple-definition" \
#   ${@}

if [ "${1:-""}" = "" ]; then
  for dir in "${packages[@]}"; do
    pushd "$dir"
      ginkgo -r -p --race -randomizeAllSpecs -randomizeSuites \
        -ldflags="-extldflags=-Wl,--allow-multiple-definition" \
        ${@:2}
    popd
  done
  for dir in "${serial_packages[@]}"; do
    pushd "$dir"
      ginkgo -r --race -randomizeAllSpecs -randomizeSuites -failFast \
        -ldflags="-extldflags=-Wl,--allow-multiple-definition" \
        ${@:2}
    popd
  done
else
  dir="${@: -1}"
  dir="${dir#./}"
  for package in "${serial_packages[@]}"; do
    if [[ "${dir##$package}" != "${dir}" ]]; then
      ginkgo -r -randomizeAllSpecs -randomizeSuites -failFast \
        -ldflags="-extldflags=-Wl,--allow-multiple-definition" \
        "${@}"
      exit $?
    fi
  done
  ginkgo -r -p -randomizeAllSpecs -randomizeSuites -failFast \
    -ldflags="-extldflags=-Wl,--allow-multiple-definition" \
    "${@}"
fi
