require 'rspec'
require 'bosh/template/test'
require 'yaml'
require 'json'

module Bosh::Template::Test
  describe 'cni-wrapper-plugin.conf.erb' do
    describe 'template rendering' do
      let(:release_path) {File.join(File.dirname(__FILE__), '../..')}
      let(:release) {ReleaseDir.new(release_path)}

      describe 'cni job' do
        let(:job) {release.job('cni')}
        describe 'config/cni/cni-wrapper-plugin.conf' do
          let(:template) {job.template('config/cni/cni-wrapper-plugin.conf')}

          context 'when multiple networks are present' do
            let(:merged_manifest_properties) { {} }
            let(:instance_spec) { InstanceSpec.new(networks: networks) }
            let(:networks) do
              {
                'network1' => {'ip' => '1.2.3.4'},
                'network2' => {'ip' => '2.3.4.5'}
              }
            end

            it 'renders the bosh network ips into the manifest' do
              parsed_conf = JSON.parse(template.render(merged_manifest_properties, spec: instance_spec))
              expect(parsed_conf['underlay_ips']).to contain_exactly('1.2.3.4', '2.3.4.5')
            end
          end
        end
      end
    end
  end
end