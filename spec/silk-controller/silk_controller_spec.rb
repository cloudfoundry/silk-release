require 'rspec'
require 'bosh/template/test'
require 'yaml'
require 'json'

module Bosh::Template::Test
  describe 'silk-controller job' do
    let(:release_path) {File.join(File.dirname(__FILE__), '../..')}
    let(:release) {ReleaseDir.new(release_path)}
    let(:merged_manifest_properties) do
      {
        'disable' => false,
        'network' => '10.255.0.1/12',
        'subnet_prefix_length' => 30,
        'subnet_lease_expiration_hours' => 2,
        'debug_port' => 1234,
        'health_check_port' => 2345,
        'health_check_timeout_seconds' => 11,
        'listen_ip' => '123.123.2.2',
        'listen_port' => 2222,
        'metron_port' => 2222,
        'database' => {
          'type' => 'postgres',
          'host' => 'some-database-host',
          'username' => 'some-database-username',
          'password' => 'some-database-password',
          'port' => 5678,
          'name' => 'some-database-name',
          'require_ssl' => true,
          'ca_cert' => 'some ca cert',
          'connect_timeout_seconds' => 10,
          'skip_hostname_validation' => true,
        },
        'max_open_connections' => 1,
        'connections_max_lifetime_seconds' => 31
      }
    end
    let(:database_link) {
      Link.new(
        name: 'database',
        instances: [LinkInstance.new()],
        properties: {}
      )
    }

    let(:job) {release.job('silk-controller')}

    describe 'database_ca.crt' do
      let(:template) {job.template('config/certs/database_ca.crt')}
      it 'writes the content of database.ca_cert' do
        merged_manifest_properties['database']['ca_cert'] = 'the ca cert'
        expect(template.render(merged_manifest_properties)).to eq('the ca cert')
      end
    end

    describe 'silk-controller.json.erb' do
      let(:template) {job.template('config/silk-controller.json')}

      it 'creates a config/silk-controller.json from properties' do
        config = JSON.parse(template.render(merged_manifest_properties))
        expect(config).to eq({
          'debug_server_port' => 1234,
          'health_check_port' => 2345,
          'listen_host' => '123.123.2.2',
          'listen_port' => 2222,
          'ca_cert_file' => '/var/vcap/jobs/silk-controller/config/certs/ca.crt',
          'server_cert_file' => '/var/vcap/jobs/silk-controller/config/certs/server.crt',
          'server_key_file' => '/var/vcap/jobs/silk-controller/config/certs/server.key',
          'network' => '10.255.0.1/12',
          'subnet_prefix_length' => 30,
          'database' => {
            'type' => 'postgres',
            'user' => 'some-database-username',
            'password' => 'some-database-password',
            'host' => 'some-database-host',
            'port' => 5678,
            'timeout' => 10,
            'database_name' => 'some-database-name',
            'require_ssl' => true,
            'ca_cert' => '/var/vcap/jobs/silk-controller/config/certs/database_ca.crt',
            'skip_hostname_validation' => true,
          },
          'lease_expiration_seconds' => 60 * 60 * 2,
          'metron_port' => 2222,
          'staleness_threshold_seconds' => 60*60,
          'metrics_emit_seconds' => 30,
          'log_prefix' => 'cfnetworking',
          'max_idle_connections' => 10,
          'max_open_connections' => 1,
          'connections_max_lifetime_seconds' => 31
        })
      end

      it 'uses the database link for host when the property is not set' do
        merged_manifest_properties['database'].delete('host')
        config = JSON.parse(template.render(merged_manifest_properties, consumes: [database_link]))
        expect(config['database']['host']).to eq('link.instance.address.com')
      end

      context 'when ips have leading 0s' do
        it 'network fails with a nice message' do
          merged_manifest_properties['network'] = '10.255.0.01/12'
          expect {
            template.render(merged_manifest_properties, consumes: [database_link])
          }.to raise_error (/Invalid network/)
        end

        it 'listen_ip fails with a nice message' do
          merged_manifest_properties['listen_ip'] = '0.01.0.0'
          expect {
            template.render(merged_manifest_properties, consumes: [database_link])
          }.to raise_error (/Invalid listen_ip/)
        end
      end

      let(:empty_link) {
        Link.new(
          name: 'database',
          instances: [],
          properties: {}
        )
      }

      it 'raises an error when the database property is not set and the link has no instances' do
        merged_manifest_properties['database'].delete('host')
        expect{
          JSON.parse(template.render(merged_manifest_properties, consumes: [empty_link]))
        }.to raise_error('must provide database link or set database.host')
      end

      it 'raises an error when neither database link or host param are set' do
        merged_manifest_properties['database'].delete('host')
        expect{
          JSON.parse(template.render(merged_manifest_properties))
        }.to raise_error('must provide database link or set database.host')
      end

      it 'raises an error when given a value greater than 30 for subnet prefix length' do
        merged_manifest_properties['subnet_prefix_length'] = 100 
        expect{
          JSON.parse(template.render(merged_manifest_properties))
        }.to raise_error('subnet_prefix_length must be a value between 1-30')
      end

      it 'raises an error when given a value less than 1 for subnet prefix length' do
        merged_manifest_properties['subnet_prefix_length'] = -10
        expect{
          JSON.parse(template.render(merged_manifest_properties))
        }.to raise_error('subnet_prefix_length must be a value between 1-30')
      end

      it 'raises an error when the driver (type) is unknown' do
        merged_manifest_properties['database']['type'] = 'bar'
        expect {
          JSON.parse(template.render(merged_manifest_properties))
        }.to raise_error('unknown driver bar')
      end

      it 'raises an error when the driver (type) is missing' do
        merged_manifest_properties['database'].delete('type')
        expect {
          JSON.parse(template.render(merged_manifest_properties))
        }.to raise_error('database.type must be specified')
      end

      it 'raises an error when missing username' do
        merged_manifest_properties['database'].delete('username')
        expect {
          JSON.parse(template.render(merged_manifest_properties))
        }.to raise_error('database.username must be specified')
      end

      it 'raises an error when missing password' do
        merged_manifest_properties['database'].delete('password')
        expect {
          JSON.parse(template.render(merged_manifest_properties))
        }.to raise_error('database.password must be specified')
      end

      it 'raises an error when missing port' do
        merged_manifest_properties['database'].delete('port')
        expect {
          JSON.parse(template.render(merged_manifest_properties))
        }.to raise_error('database.port must be specified')
      end

      it 'raises an error when missing name' do
        merged_manifest_properties['database'].delete('name')
        expect {
          JSON.parse(template.render(merged_manifest_properties))
        }.to raise_error('database.name must be specified')
      end
    end
  end
end
