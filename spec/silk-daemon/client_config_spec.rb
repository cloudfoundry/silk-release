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
        {}
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
        end
      end
    end
  end
end
