$ErrorActionPreference = "Stop";
trap { $host.SetShouldExit(1) }

$env:GOPATH=$PWD

go get github.com/onsi/ginkgo/ginkgo

# Force system temp dir to be on the ephemeral disk
if (Test-Path env:EPHEMERAL_DISK_TEMP_PATH) {
  mkdir "$env:EPHEMERAL_DISK_TEMP_PATH" -ea 0
  $env:TEMP = $env:TMP = $env:GOTMPDIR = $env:EPHEMERAL_DISK_TEMP_PATH
}

& "$env:GOPATH/bin/ginkgo.exe" -nodes $env:NODES -r -race -keepGoing `
  -randomizeSuites -skipPackage linux src/vxlan-policy-agent
Exit $LastExitCode
