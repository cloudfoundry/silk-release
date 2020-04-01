require 'rspec'
require 'bosh/template/test'
require 'yaml'
require 'json'


module Bosh::Template::Test
  describe 'iptables-logger.json.erb' do
    describe 'template rendering' do
      let(:release_path) {File.join(File.dirname(__FILE__), '../..')}
      let(:release) {ReleaseDir.new(release_path)}
      let(:merged_manifest_properties) do
        {
          'kernel_log_file' => 'mylog.file',
          'metron_port' => 12345,
          'disable' => false,
          'logging' => { 'format' => { 'timestamp' => 'rfc3339' }},
        }
      end
      let(:spec) do
        InstanceSpec.new(ip: '1.2.3.4', id: 'some-guid')
      end

      describe 'iptables-logger job' do let(:job) {release.job('iptables-logger')}
        describe 'config/iptables-logger.json' do
          let(:template) {job.template('config/iptables-logger.json')}

          it 'renders the template with the provided manifest properties' do
            clientConfig = JSON.parse(template.render(merged_manifest_properties, spec: spec))
            expect(clientConfig).to eq({
              'kernel_log_file' => 'mylog.file',
              'container_metadata_file' => '/var/vcap/data/container-metadata/store.json',
              'output_log_file' => '/var/vcap/sys/log/iptables-logger/iptables.log',
              'metron_address' => '127.0.0.1:12345',
              'host_ip' => '1.2.3.4',
              'host_guid' => 'some-guid',
              'log_timestamp_format' => 'rfc3339',
            })
          end

          context 'when logging.format.timestamp is set to an invalid value' do
            let(:merged_manifest_properties) do
              {
                'logging' => {'format' => {'timestamp' => 'meow' }}
              }
            end
            it 'throws a helpful error' do
              expect {
                template.render(merged_manifest_properties, spec: spec)
              }.to raise_error("'meow' is not a valid timestamp format for the property 'logging.format.timestamp'. Valid options are: 'rfc3339' and 'deprecated'.")
            end
          end
        end
      end
    end
  end
end
