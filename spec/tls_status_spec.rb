# frozen_string_literal: true

require_relative 'shared_examples'

RSpec.describe InternetSecurityEvent::TLSStatus do
  subject do
    InternetSecurityEvent::TLSStatus.new(hostname, certificate)
  end

  let(:hostname) { 'example.com' }

  include_examples 'with an X.509 certificate'

  context 'with a non-matching certificate' do
    let(:certificate_hostname) { 'example.net' }

    it 'state is correct' do
      expect(subject.to_e[:state]).to eq('critical')
    end

    it 'description is correct' do
      expect(subject.to_e[:description]).to eq('certificate subject does not match hostname')
    end
  end

  context 'with a wildcard certificate' do
    let(:certificate_hostname) { '*.example.com' }

    context 'with a domain matching wildcard' do
      let(:hostname) { 'www.example.com' }

      it 'should have an ok state' do
        expect(subject.to_e[:state]).to eq('ok')
      end
    end

    context 'with a domain not matching wildcard' do
      let(:hostname) { 'api.preprod.example.com' }

      it 'should have an ok state' do
        expect(subject.to_e[:state]).to eq('critical')
      end
    end
  end
end
