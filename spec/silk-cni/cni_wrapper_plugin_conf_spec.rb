require 'rspec'
require 'bosh/template/test'
require 'yaml'
require 'json'


module Bosh::Template::Test
  describe 'silk-cni job' do
    let(:release_path) {File.join(File.dirname(__FILE__), '../..')}
    let(:release) {ReleaseDir.new(release_path)}
    let(:merged_manifest_properties) do
      {
        'mtu' => mtu,
        'silk_daemon' => {
          'listen_port' => 8080
        },
        'iptables_logging' => true,
        'no_masquerade_cidr_range' => '222.22.0.0/16',
        'dns_servers' => ['8.8.8.8'],
        'rate' => 100,
        'burst' => 200,
        'iptables_denied_logs_per_sec' => 2,
        'iptables_accepted_udp_logs_per_sec' => 3,
        'host_tcp_services' => ['169.254.0.2:9001', '169.254.0.2:9002']
      }
    end
    let(:job) {release.job('silk-cni')}
    let(:mtu) {0}
    let(:disable) {false}
    let(:networks) {{'fake-network' => {'fake-network-settings' => {}, 'ip' => '192.74.65.4'}}}
    let(:spec) {InstanceSpec.new(networks: networks, ip: '111.11.11.1')}


    describe 'cni-wrapper-plugin.conflist' do
      let(:template) {job.template('config/cni/cni-wrapper-plugin.conflist')}

      it 'creates a config/cni/cni-wrapper-plugin.conflist from properties' do
        clientConfig = JSON.parse(template.render(merged_manifest_properties, spec: spec))
        expect(clientConfig).to eq({
          'name' => 'cni-wrapper',
          'cniVersion' => '0.3.1',
          'plugins' => [{
            'type' => 'cni-wrapper-plugin',
            'datastore' => '/var/vcap/data/container-metadata/store.json',
            'iptables_lock_file' => '/var/vcap/data/garden-cni/iptables.lock',
            'instance_address' => '111.11.11.1',
            'no_masquerade_cidr_range' => '222.22.0.0/16',
            'temporary_underlay_interface_names' => [],
            'underlay_ips' => ['192.74.65.4'],
            'iptables_asg_logging' => true,
            'iptables_c2c_logging' => true,
            'iptables_denied_logs_per_sec' => 2,
            'iptables_accepted_udp_logs_per_sec' => 3,
            'ingress_tag' => 'ffff0000',
            'vtep_name' => 'silk-vtep',
            'dns_servers' => ['8.8.8.8'],
            'host_tcp_services' => ['169.254.0.2:9001', '169.254.0.2:9002'],
            'delegate' => {
              'cniVersion' => '0.3.1',
              'name' => 'silk',
              'type' => 'silk-cni',
              'daemonPort' => 8080,
              'dataDir' => '/var/vcap/data/host-local',
              'datastore' => '/var/vcap/data/silk/store.json',
              'mtu' => 0,
              'bandwidthLimits' => {
                'rate' => 100 * 1024,
                'burst' => 200 * 1024
              }
            }
          }]
        })
      end

      context 'when no_masquerade_cidr_range is not provided' do
        let(:merged_manifest_properties) {}
        it 'does not set the no_masquerade_cidr_range' do
          clientConfig = JSON.parse(template.render(merged_manifest_properties, spec: spec))
          expect(clientConfig['plugins'][0]['no_masquerade_cidr_range']).to eq('')
        end

        context 'when a cf_network.network link exists' do
          let(:links) {[
            Link.new(
              name: 'cf_network',
              properties: {
                'network' => '10.255.0.0/16'
              }
            )
          ]}

          it 'fallsback to the cf_network.network link property' do
            clientConfig = JSON.parse(template.render(merged_manifest_properties, spec: spec, consumes: links))
            expect(clientConfig['plugins'][0]['no_masquerade_cidr_range']).to eq('10.255.0.0/16')
          end
        end
      end

      context 'when mtu is greater than 0' do
        let(:mtu) {100}
        it 'subtracts VXLAN_OVERHEAD from the mtu value' do
          clientConfig = JSON.parse(template.render(merged_manifest_properties, spec: spec))
          expect(clientConfig['plugins'][0]['delegate']['mtu']).to eq(50)
        end
      end
    end
  end
end
