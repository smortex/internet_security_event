# frozen_string_literal: true

RSpec.describe Resolv::DNS::Resource::IN::TLSA do
  subject do
    Resolv::DNS::Resource::IN::TLSA.new(raw_record_data)
  end

  context 'with the TLSA record "3 0 1 015ad9a7cb61431733b483cd7e155f38f7a776fa0ef7f0ed94da3ca8d86c210a"' do
    let(:raw_record_data) do
      "\x03\x00\x01\x01\x5a\xd9\xa7\xcb\x61\x43\x17\x33\xb4\x83\xcd\x7e\x15\x5f\x38" \
                  "\xf7\xa7\x76\xfa\x0e\xf7\xf0\xed\x94\xda\x3c\xa8\xd8\x6c\x21\x0a"
    end

    describe '#certificate_usage' do
      it { is_expected.to have_attributes(certificate_usage: 3) }
    end

    describe '#selector' do
      it { is_expected.to have_attributes(selector: 0) }
    end

    describe '#matching_type' do
      it { is_expected.to have_attributes(matching_type: 1) }
    end

    describe '#certificate_association_data' do
      it { is_expected.to have_attributes(certificate_association_data: '015ad9a7cb61431733b483cd7e155f38f7a776fa0ef7f0ed94da3ca8d86c210a') }
    end
  end
end
