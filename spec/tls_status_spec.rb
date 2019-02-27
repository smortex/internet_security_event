# frozen_string_literal: true

require_relative 'shared_examples'

RSpec.describe InternetSecurityEvent::TLSStatus do
  let(:tls_status) { InternetSecurityEvent::TLSStatus.new(hostname, certificate) }
  let(:hostname) { 'example.com' }

  include_examples 'with an X.509 certificate'

  context '#to_e' do
    subject { tls_status.to_e }

    include_examples 'InternetSecurityEvent::X509Status#to_e'

    context 'with a non-matching certificate' do
      let(:certificate_hostname) { 'example.net' }

      include_examples 'certificate does not match hostname'
    end

    context 'with a wildcard certificate' do
      let(:certificate_hostname) { '*.example.com' }

      context 'with a domain matching wildcard' do
        let(:hostname) { 'www.example.com' }

        include_examples 'certificate is valid'
      end

      context 'with a domain not matching wildcard' do
        let(:hostname) { 'api.preprod.example.com' }

        include_examples 'certificate does not match hostname'
      end
    end
  end
end
