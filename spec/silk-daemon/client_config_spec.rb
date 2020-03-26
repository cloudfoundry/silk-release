require 'rspec'
require 'bosh/template/test'
require 'yaml'
require 'json'


module Bosh::Template::Test
  describe 'client-config.json.erb' do
    describe 'template rendering' do
      let(:release_path) {File.join(File.dirname(__FILE__), '../..')}
      let(:release) {ReleaseDir.new(release_path)}
      let(:merged_manifest_properties) do
        {
          'listen_port' => 12345,
          'vtep_name' => 'silk-vtep',
          'silk_controller' => {
            'hostname' => 'some-host',
            'listen_port' => 12345,
          },
          'ca_cert_file' => '/var/vcap/jobs/silk-daemon/config/certs/ca.crt',
          'client_cert_file' => '/var/vcap/jobs/silk-daemon/config/certs/client.crt',
          'client_key_file' => '/var/vcap/jobs/silk-daemon/config/certs/client.key',
          'datastore' => '/var/vcap/data/silk/store.json',
          'partition_tolerance_hours' => 1,
          'client_timeout_seconds' => 5,
          'debug_port' => 89,
          'metron_port' => 5678,
          'vtep_port' => 6666,
          'log_prefix' => 'cfnetworking',
          'single_ip_only' => true,
          'logging' => {'format' => {'timestamp' => 'rfc3339' }}
        }
      end

      links = [
        Link.new(
          name: 'cf_network',
          instances: [LinkInstance.new()],
          properties: {
            'network' => '10.255.0.0/16',
            'subnet_prefix_length' => 24
          }
        )
      ]

      describe 'silk-daemon job' do let(:job) {release.job('silk-daemon')}
        describe 'config/client-config.json' do
          let(:template) {job.template('config/client-config.json')}

          it 'renders the template with the provided manifest properties' do
            clientConfig = JSON.parse(template.render(merged_manifest_properties, consumes: links))
            expect(clientConfig).to eq({
              'underlay_ip' => '192.168.0.0',
              'subnet_prefix_length' => 24,
              'overlay_network' => '10.255.0.0/16',
              'health_check_port' => 12345,
              'vtep_name' => 'silk-vtep',
              'connectivity_server_url' => 'https://some-host:12345',
              'ca_cert_file' => '/var/vcap/jobs/silk-daemon/config/certs/ca.crt',
              'client_cert_file' => '/var/vcap/jobs/silk-daemon/config/certs/client.crt',
              'client_key_file' => '/var/vcap/jobs/silk-daemon/config/certs/client.key',
              'vni' => 1,
              'poll_interval' => 30,
              'debug_server_port' => 89,
              'datastore' => '/var/vcap/data/silk/store.json',
              'partition_tolerance_seconds' => 3600,
              'client_timeout_seconds' => 5,
              'metron_port' => 5678,
              'vtep_port' => 6666,
              'log_prefix' => 'cfnetworking',
              'vxlan_interface_name' => '',
              'single_ip_only' => true
            })
          end

          context 'when temporary_vxlan_interface and vxlan_network are set' do
            let(:merged_manifest_properties) do
              {
                'temporary_vxlan_interface' => 'some-vxlan-interface',
                'vxlan_network' => 'some-vxlan-network'
              }
            end

            it 'throws a helpful error' do
              expect {
                template.render(merged_manifest_properties, consumes: links)
              }.to raise_error("Cannot specify both 'temporary_vxlan_interface' and 'vxlan_network' properties.")
            end
          end

          context 'when temporary_vxlan_interface is set' do
            let(:merged_manifest_properties) do
              {
                'temporary_vxlan_interface' => 'some-vxlan-interface',
              }
            end

            it 'sets vxlan_interface_name' do
              clientConfig = JSON.parse(template.render(merged_manifest_properties, consumes: links))
              expect(clientConfig['vxlan_interface_name']).to eq("some-vxlan-interface")
            end
          end

          context 'when vxlan_network is set' do
            let(:merged_manifest_properties) do
              {
                'vxlan_network' => 'fake-network'
              }
            end
            networks = { 'fake-network' => { 'fake-network-settings' => {}, 'ip' => "192.74.65.4" } }
            spec = InstanceSpec.new(address: 'cloudfoundry.org', bootstrap: true, networks: networks)

            it 'sets the underlay_ip to the ip associated with vxlan_network' do
              clientConfig = JSON.parse(template.render(merged_manifest_properties, consumes: links, spec: spec))
              expect(clientConfig['underlay_ip']).to eq("192.74.65.4")
            end
          end

          context 'when logging.format.timestamp is set to an invalid value' do
            let(:merged_manifest_properties) do
              {
                'logging' => {'format' => {'timestamp' => 'meow' }}
              }
            end
            it 'throws a helpful error' do
              expect {
                template.render(merged_manifest_properties, consumes: links)
              }.to raise_error("'meow' is not a valid timestamp format for the property 'logging.format.timestamp'. Valid options are: 'rfc3339' and 'deprecated'.")
            end
          end
        end
      end
    end
  end
end
