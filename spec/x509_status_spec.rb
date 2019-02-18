# frozen_string_literal: true

require_relative 'shared_examples'

RSpec.describe InternetSecurityEvent::X509Status do
  subject do
    InternetSecurityEvent::X509Status.new(certificate)
  end

  include_examples 'with an X.509 certificate'

  context '#renewal_duration' do
    context 'with a valid long lasting X.509 certificate' do
      include_examples 'with a certificate valid for 2 years'

      it 'should have a 90 days renewal duration' do
        expect(subject.send(:renewal_duration)).to eq(90.days)
      end
    end

    context 'with a certificate valid 30 days' do
      include_examples 'with a certificate valid for 30 days'

      it 'should have a 10 days renewal duration' do
        expect(subject.send(:renewal_duration)).to eq(10.days)
      end
    end
  end
end
