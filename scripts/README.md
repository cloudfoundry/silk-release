# Scripts

This is the README for our scripts. To learn more about `silk-release`, go to the main [README](../README.md).

| Name | Purpose | Notes |
| --- | --- | --- |
| commit-with-submodule-log | lightweight script for submodule bumps, allows for commits that don't finish a story | depends on submodule-log |
| docker-shell | starts a docker image based on a database, use `db=` to set `mysql` or `mysql-5.6` or `postgres` | |
| docker-test | uses docker-shell to run test.sh | |
| fly-execute | runs the database tests on concourse for the given `db=`: `mysql` or `mysql-5.6` or `postgres`| |
| reconfigure | fly reconfigures the silk pipeline | |
| submodule-log | prints the cached submodule log and if you provide story id(s) will add finishes tag(s) | |
| sync-package-specs | updates the package spec files for our release | |
| template-tests | runs the template spec tests for the release | |
| test-windows.ps1 | runs the vxlan-policy-agent tests on windows | |
| test.sh | runs all the component tests for silk-release | |
| update | updates all submodules | |
| winc-sync-package-specs | updates the package spec files for vxlan-policy-agent-windows | |
