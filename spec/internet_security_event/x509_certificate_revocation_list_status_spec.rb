# frozen_string_literal: true

require_relative '../shared_examples'

RSpec.describe InternetSecurityEvent::X509CertificateRevocationListStatus do
  subject { x509_status }

  let(:x509_status) { described_class.new(crl) }

  include_examples 'with an X.509 certificate revocation list'

  describe '#to_e' do
    subject { x509_status.to_e }

    include_examples 'InternetSecurityEvent::X509Status#to_e'
  end

  describe '#renewal_duration' do
    context 'with a valid long lasting X.509 crl' do
      include_examples 'with a 2 years duration'

      it { is_expected.to have_attributes(renewal_duration: 90.days) }
    end

    context 'with a crl valid 30 days' do
      include_examples 'with a 30 days duration'

      it { is_expected.to have_attributes(renewal_duration: 10.days) }
    end
  end
end
