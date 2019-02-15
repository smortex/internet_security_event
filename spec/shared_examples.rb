# frozen_string_literal: true

require 'active_support/core_ext/integer/time'
require 'openssl'

RSpec.shared_examples 'with an X.509 certificate' do
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

  context 'with a valid certificate' do
    it 'state is correct' do
      expect(subject.to_e[:state]).to eq('ok')
    end

    it 'description is correct' do
      expect(subject.to_e[:description]).to eq('certificate will expire in about 1 month')
    end
  end

  context 'with a certificate about to expire' do
    let(:not_after) { Time.now + 3600 * 24 * 5 }

    it 'state is correct' do
      expect(subject.to_e[:state]).to eq('warn')
    end

    it 'description is correct' do
      expect(subject.to_e[:description]).to eq('certificate will expire in 5 days')
    end
  end

  context 'with a certificate expiring really soon' do
    let(:not_after) { Time.now + 3600 * 12 }

    it 'state is correct' do
      expect(subject.to_e[:state]).to eq('critical')
    end

    it 'description is correct' do
      expect(subject.to_e[:description]).to eq('certificate will expire in about 12 hours')
    end
  end

  context 'with a not valid yet certificate' do
    let(:not_before) { Time.now + 3600 }

    it 'state is correct' do
      expect(subject.to_e[:state]).to eq('critical')
    end

    it 'description is correct' do
      expect(subject.to_e[:description]).to eq('certificate will become valid in about 1 hour')
    end
  end

  context 'with an expired certificate' do
    let(:not_after) { Time.now - 3600 }

    it 'state is correct' do
      expect(subject.to_e[:state]).to eq('critical')
    end

    it 'description is correct' do
      expect(subject.to_e[:description]).to eq('certificate has expired about 1 hour ago')
    end
  end
end

