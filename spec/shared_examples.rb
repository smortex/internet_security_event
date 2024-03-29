# frozen_string_literal: true

require 'active_support/core_ext/integer/time'
require 'openssl'

RSpec.shared_context 'with a 2 years duration' do
  let(:not_before) { Time.now - 2.days }
  let(:not_after)  { Time.now + 2.years - 2.days }
end

RSpec.shared_context 'with a 30 days duration' do
  let(:not_before) { Time.now - 2.days }
  let(:not_after)  { Time.now + 30.days - 2.days }
end

RSpec.shared_examples 'certificate is valid' do
  it { is_expected.to include(state: 'ok') }
end

RSpec.shared_examples 'certificate does not match hostname' do
  it { is_expected.to include(state: 'critical') }
  it { is_expected.to include(description: 'certificate subject does not match hostname') }
end

RSpec.shared_context 'with an X.509 certificate' do
  let(:certificate_hostname) { 'example.com' }
  let(:certificate) do
    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{certificate_hostname}")
    cert.not_before = not_before
    cert.not_after  = not_after
    cert
  end

  let(:not_before) { Time.now.utc - 1.day }
  let(:not_after)  { Time.now.utc + 30.days }
end

RSpec.shared_context 'with an X.509 certificate revocation list' do
  let(:crl) do
    crl = OpenSSL::X509::CRL.new
    crl.last_update = not_before
    crl.next_update = not_after
    crl
  end

  let(:not_before) { Time.now.utc - 1.day }
  let(:not_after)  { Time.now.utc + 30.days }
end

RSpec.shared_examples 'InternetSecurityEvent::X509Status#to_e' do
  context 'with a valid certificate' do
    it { is_expected.to include(state: 'ok') }
    it { is_expected.to include(description: /\A(certificate|crl) will expire in about 1 month\z/) }
  end

  context 'with a certificate about to expire' do
    let(:not_before) { Time.now - 75.days }
    let(:not_after)  { Time.now + 15.days }

    it { is_expected.to include(state: 'warning') }
    it { is_expected.to include(description: /\A(certificate|crl) will expire in 15 days\z/) }
  end

  context 'with a certificate expiring really soon' do
    let(:not_before) { Time.now - 85.days }
    let(:not_after)  { Time.now + 5.days }

    it { is_expected.to include(state: 'critical') }
    it { is_expected.to include(description: /\A(certificate|crl) will expire in 5 days\z/) }
  end

  context 'with a not valid yet certificate' do
    let(:not_before) { Time.now + 2.days }
    let(:not_after)  { Time.now + 92.days }

    it { is_expected.to include(state: 'critical') }
    it { is_expected.to include(description: /\A(certificate|crl) will become valid in 2 days\z/) }
  end

  context 'with an expired certificate' do
    let(:not_before) { Time.now - 92.days }
    let(:not_after)  { Time.now - 2.days }

    it { is_expected.to include(state: 'critical') }
    it { is_expected.to include(description: /\A(certificate|crl) has expired 2 days ago\z/) }
  end
end
