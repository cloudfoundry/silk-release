require 'rspec'
require 'bosh/template/test'
require 'yaml'
require 'json'


module Bosh::Template::Test
  describe 'vxlan-policy-agent.json.erb' do
    describe 'template rendering' do
      let(:release_path) {File.join(File.dirname(__FILE__), '../..')}
      let(:release) {ReleaseDir.new(release_path)}
      let(:merged_manifest_properties) do
        {
          'log_level' => 'error',
          'iptables_logging' => true,
          'iptables_accepted_udp_logs_per_sec' => 33,
          'policy_poll_interval_seconds' => 22,
          'asg_poll_interval_seconds' => 66,
          'enable_asg_syncing' => false,
          'policy_server' => {
            'hostname' => 'policy-server-hostname',
            'internal_listent_port' => 234,
          },
          'metron_port' => 55,
          'enable_overlay_ingress_rules' => true,
        }
      end

      let(:links) do
        [
          Link.new(
            name: 'cf_network',
            instances: [LinkInstance.new()],
            properties: {
              'network' => '10.255.0.0/16',
            }
          ),
          Link.new(
            name: 'cni_config',
            instances: [LinkInstance.new()],
            properties: {
              'iptables_logging' => true,
              'iptables_denied_logs_per_sec' => 2,
              'deny_networks' => {
                'always' => ['1.1.1.1/32'],
                'running' => ['2.2.2.2/32'],
                'staging' => ['3.3.3.3/32'],
              },
              'outbound_connections' => {
                'limit' => true,
                'burst' => 1000,
                'rate_per_sec' => 100,
              }
            }
          )
        ]
      end

      describe 'vxlan-policy-agent job' do
        let(:job) {release.job('vxlan-policy-agent')}
        let(:spec) do
          InstanceSpec.new(address: '1.2.3.4', id: 'some-guid', deployment: 'some-deployment', name: 'vxlan-policy-agent')
        end

        describe 'config/client-config.json' do
          let(:template) {job.template('config/vxlan-policy-agent.json')}

          it 'renders the template with the provided manifest properties' do
            renderedConfig = JSON.parse(template.render(merged_manifest_properties, consumes: links))
            expect(renderedConfig).to eq({
              'ca_cert_file' => '/var/vcap/jobs/vxlan-policy-agent/config/certs/ca.crt',
              'client_cert_file' => '/var/vcap/jobs/vxlan-policy-agent/config/certs/client.crt',
              'client_key_file' => '/var/vcap/jobs/vxlan-policy-agent/config/certs/client.key',
              'client_timeout_seconds' => 5,
              'cni_datastore_path' => '/var/vcap/data/container-metadata/store.json',
              'debug_server_host' => '127.0.0.1',
              'debug_server_port' => 8721,
              'iptables_accepted_udp_logs_per_sec' => 33,
              'iptables_c2c_logging' => true,
              'iptables_lock_file' => '/var/vcap/data/garden-cni/iptables.lock',
              'log_level' => 'error',
              'log_prefix' => 'cfnetworking',
              'underlay_ips' => ['192.168.0.0'],
              'metron_address' => '127.0.0.1:55',
              'enable_overlay_ingress_rules' => true,
              'policy_server_url' => 'https://policy-server-hostname:4003',
              'poll_interval' => 22,
              'enable_asg_syncing' => false,
              'asg_poll_interval' => 66,
              'vni' => 1,
              'force_policy_poll_cycle_host' => '127.0.0.1',
              'force_policy_poll_cycle_port' => 8722,
              'disable_container_network_policy' => false,
              'overlay_network' => '10.255.0.0/16',
              'iptables_asg_logging' => true,
              'iptables_denied_logs_per_sec' => 2,
              'deny_networks' => {
                'always' => ['1.1.1.1/32'],
                'running' => ['2.2.2.2/32'],
                'staging' => ['3.3.3.3/32'],
              },
              'outbound_connections' => {
                'limit' => true,
                'logging' => true,
                'burst' => 1000,
                'rate_per_sec' => 100,
              },
              'loggregator' => {
                'loggregator_use_v2_api' => false,
              }
            })
          end

          context 'when loggregator.use_v2_api is true' do
            let(:ca_cert_template) {job.template('config/certs/loggregator/ca.crt')}
            let(:client_cert_template) {job.template('config/certs/loggregator/client.crt')}
            let(:client_key_template) {job.template('config/certs/loggregator/client.key')}

            before do
              merged_manifest_properties['loggregator'] = {
                'use_v2_api' => true,
                'ca_cert' => 'some-ca-cert',
                'cert' => 'some-client-cert',
                'key' => 'some-client-key'
              }
            end

            it 'renders the loggregator config as well' do
              renderedConfig = JSON.parse(template.render(merged_manifest_properties, consumes: links, spec: spec))
              expect(renderedConfig['loggregator']).to eq({
                'loggregator_use_v2_api' => true,
                'loggregator_api_port' => 3458,
                'loggregator_ca_path' => '/var/vcap/jobs/vxlan-policy-agent/config/certs/loggregator/ca.crt',
                'loggregator_cert_path' => '/var/vcap/jobs/vxlan-policy-agent/config/certs/loggregator/client.crt',
                'loggregator_key_path' => '/var/vcap/jobs/vxlan-policy-agent/config/certs/loggregator/client.key',
                'loggregator_job_deployment' => 'some-deployment',
                'loggregator_job_name' => 'vxlan-policy-agent',
                'loggregator_job_index' => 'some-guid',
                'loggregator_job_ip' => '1.2.3.4',
                'loggregator_job_origin' => "vxlan-policy-agent",
                'loggregator_source_id' => "vxlan-policy-agent",
                'loggregator_instance_id' => 'some-guid'
              })
            end

            it 'renders the ca cert' do
              rendered_ca_cert = ca_cert_template.render(merged_manifest_properties)
              expect(rendered_ca_cert).to eq("\nsome-ca-cert\n\n")
            end

            it 'renders the client cert' do
              rendered_client_cert = client_cert_template.render(merged_manifest_properties)
              expect(rendered_client_cert).to eq("\nsome-client-cert\n\n")
            end

            it 'renders the ca cert' do
              rendered_client_key = client_key_template.render(merged_manifest_properties)
              expect(rendered_client_key).to eq("\nsome-client-key\n\n")
            end
          end
        end
      end
    end
  end
end
