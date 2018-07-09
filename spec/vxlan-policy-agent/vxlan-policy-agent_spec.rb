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
          'policy_server' => {
            'hostname' => 'policy-server-hostname',
            'internal_listent_port' => 234,
          },
          'metron_port' => 55,
          'debug_server_port' => 343,
          'enable_overlay_ingress_rules' => true,
        }
      end

      describe 'vxlan-policy-agent job' do
        let(:job) {release.job('vxlan-policy-agent')}
        describe 'config/client-config.json' do
          let(:template) {job.template('config/vxlan-policy-agent.json')}

          it 'renders the template with the provided manifest properties' do
            renderedConfig = JSON.parse(template.render(merged_manifest_properties))
            expect(renderedConfig).to eq({
              'ca_cert_file' => '/var/vcap/jobs/vxlan-policy-agent/config/certs/ca.crt',
              'client_cert_file' => '/var/vcap/jobs/vxlan-policy-agent/config/certs/client.crt',
              'client_key_file' => '/var/vcap/jobs/vxlan-policy-agent/config/certs/client.key',
              'client_timeout_seconds' => 5,
              'cni_datastore_path' => '/var/vcap/data/container-metadata/store.json',
              'debug_server_host' => '127.0.0.1',
              'debug_server_port' => 343,
              'iptables_accepted_udp_logs_per_sec' => 33,
              'iptables_c2c_logging' => true,
              'iptables_lock_file' => '/var/vcap/data/garden-cni/iptables.lock',
              'log_level' => 'error',
              'log_prefix' => 'cfnetworking',
              'metron_address' => '127.0.0.1:55',
              'enable_overlay_ingress_rules' => true,
              'policy_server_url' => 'https://policy-server-hostname:4003',
              'poll_interval' => 22,
              'vni' => 1,
            })
          end
        end
      end
    end
  end
end
