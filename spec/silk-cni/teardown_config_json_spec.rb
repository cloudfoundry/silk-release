require 'rspec'
require 'bosh/template/test'
require 'yaml'
require 'json'


module Bosh::Template::Test
  describe 'teardown-config.json.erb' do
    let(:release_path) {File.join(File.dirname(__FILE__), '../..')}
    let(:release) {ReleaseDir.new(release_path)}
    let(:job) {release.job('silk-cni')}
    let(:template) {job.template('config/teardown-config.json')}
    let(:merged_manifest_properties) { {} }

    it 'creates a config/teardown-config.json from properties' do
      clientConfig = JSON.parse(template.render(merged_manifest_properties))

      expect(clientConfig).to eq({
        'paths_to_delete' => [
          '/var/vcap/data/container-metadata',
          '/var/vcap/data/host-local',
          '/var/vcap/data/silk'
        ]
      })
    end
  end
end
