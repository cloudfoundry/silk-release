require 'rspec'
require 'bosh/template/test'
require 'yaml'
require 'json'


module Bosh::Template::Test
  describe 'cni-wrapper-plugin.conf.erb' do
    describe 'template rendering' do
      let(:release_path) {File.join(File.dirname(__FILE__), '../..')}
      let(:release) {ReleaseDir.new(release_path)}
      let(:merged_manifest_properties) do
        {
          'mtu' => mtu,
          'silk_daemon' => {
            'listen_port' => 8080
          },
          'iptables_logging' => true,
          'dns_servers' => ["8.8.8.8"],
          'rate' => 100,
          'burst' => 200,
          'iptables_denied_logs_per_sec' => 2,
          'iptables_accepted_udp_logs_per_sec' => 3
        }
      end
      let(:mtu){ 0 }
      let(:disable) { false }
      let(:networks) {{ 'fake-network' => { 'fake-network-settings' => {}, 'ip' => "192.74.65.4" } }}
      let(:spec) {InstanceSpec.new(networks: networks, ip: "111.11.11.1")}

      describe 'cni job' do
        let(:job) {release.job('cni')}

        describe 'cni-wrapper-plugin.conf' do
          let(:template) {job.template('config/cni/cni-wrapper-plugin.conf')}

          it 'creates a config/cni/cni-wrapper-plugin.conf from properties' do
            clientConfig = JSON.parse(template.render(merged_manifest_properties, spec: spec))

            expect(clientConfig).to eq({
              "name" => "cni-wrapper",
              "type" => "cni-wrapper-plugin",
              "cniVersion" => "0.3.1",
              "datastore" => "/var/vcap/data/container-metadata/store.json",
              "iptables_lock_file" => "/var/vcap/data/garden-cni/iptables.lock",
              "instance_address" => "111.11.11.1",
              "temporary_underlay_interface_names" => [],
              "underlay_ips" => ["192.74.65.4"],
              "iptables_asg_logging" => true,
              "iptables_c2c_logging" => true,
              "iptables_denied_logs_per_sec" => 2,
              "iptables_accepted_udp_logs_per_sec" => 3,
              "ingress_tag" => "ffff0000",
              "vtep_name" => "silk-vtep",
              "dns_servers" => ["8.8.8.8"],
              "delegate" => {
                "cniVersion" => "0.3.1",
                "name" => "silk",
                "type" => "silk-cni",
                "daemonPort" => 8080,
                "dataDir" => "/var/vcap/data/host-local",
                "datastore" => "/var/vcap/data/silk/store.json",
                "mtu" => 0,
                "bandwidthLimits"=> {
                  "rate" => 100 * 1024,
                  "burst" => 200 * 1024
                }
               }
            })
          end

          context 'when mtu is greater than 0' do
            let(:mtu){ 100 }
            it 'subtracts VXLAN_OVERHEAD from the mtu value' do
              clientConfig = JSON.parse(template.render(merged_manifest_properties, spec: spec))
              expect(clientConfig["delegate"]["mtu"]).to eq(50)
            end
          end
        end
      end
    end
  end
end
