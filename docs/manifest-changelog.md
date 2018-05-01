## Manifest changelog

### 0.4.0
**New Properties**
  - An optional parameter `no_masquerade_cidr_range` has been added to the `cni` job to specify which destination
    CIDR to exempt MASQUERADEing traffic from containers.
    If this is left unset and the bosh link `cf_network` is available with the property `network` set, it will use that value.
    Otherwise, an empty default value will be applied. If empty it will not exclude any ranges.
  - Add `disable` property to all jobs. When it is set to true the job will not start.
  - Rename `cni` job to `silk-cni`.
    This would require `cni_plugin_dir` and `cni_config_dir` to be set on the `garden-cni` job in `cf-networking` release
    as follows:
    - `cni_plugin_dir: /var/vcap/packages/silk-cni/bin`
    - `cni_config_dir: /var/vcap/jobs/silk-cni/config/cni`

### 0.3.0

**No manifest changes**

### 0.2.0
**New Properties**
  - An optional parameter has been added to the `silk-daemon` job to specify which bosh network should be used by the
    vxlan adapter.
    The property value is expected to be the name of a bosh network that is attached to the instance group where the
    `silk-daemon` is running.
    This is useful when running multi-homed vms. If this property is not specified, the bosh network that is the default
    gateway will be chosen.
    - `vxlan_network`

### 0.1.0
  - This release was extracted from [cf-networking-release](github.com/cloudfoundry/cf-netoworking-release).
    Refer to that release for prior changes.
