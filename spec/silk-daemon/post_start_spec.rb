require 'rspec'
require 'bosh/template/test'

module Bosh::Template::Test
  describe 'post-start.erb' do
    describe 'template rendering' do
      let(:release_path) { File.join(File.dirname(__FILE__), '../..') }
      let(:release) { ReleaseDir.new(release_path) }
      let(:job) { release.job('silk-daemon') }
      let(:template) { job.template('bin/post-start') }

      context 'when disable is false' do
        context 'when disable_checksum_offloading is true' do
          it 'disables tx-checksum-ip-generic on silk-vtep' do
            rendered = template.render({'disable_checksum_offloading' => true})
            expect(rendered).to include('ethtool -K silk-vtep tx-checksum-ip-generic off')
          end
        end

        context 'when disable_checksum_offloading is false' do
          it 'does not include an ethtool call for silk-vtep' do
            rendered = template.render({'disable_checksum_offloading' => false})
            expect(rendered).not_to include('ethtool -K silk-vtep')
          end
        end

        context 'when disable_checksum_offloading is not set' do
          it 'does not include an ethtool call for silk-vtep' do
            rendered = template.render({})
            expect(rendered).not_to include('ethtool -K silk-vtep')
          end
        end
      end

      context 'when disable is true' do
        it 'renders an empty script body' do
          rendered = template.render({'disable' => true})
          expect(rendered).not_to include('ethtool')
          expect(rendered).not_to include('wait_for_server')
        end
      end
    end
  end
end
