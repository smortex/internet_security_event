# frozen_string_literal: true

RSpec.describe Resolv::DNS::Resource::IN::TLSA do
  subject(:message) do
    m = Resolv::DNS::Message.new(0)
    m.add_answer(
      '_25._tcp.mx.blogreen.org.',
      10_800,
      described_class.new(
        described_class::CertificateUsage::DANE_EE,
        described_class::Selector::CERT,
        described_class::MatchingType::SHA2_256,
        '015ad9a7cb61431733b483cd7e155f38f7a776fa0ef7f0ed94da3ca8d86c210a',
      ),
    )
    m.add_answer(
      '_25._tcp.mx.blogreen.org.',
      10_800,
      described_class.new(
        described_class::CertificateUsage::DANE_EE,
        described_class::Selector::SPKI,
        described_class::MatchingType::SHA2_256,
        'd8aac0d602e5532136ffb9e368fbc3c9a7a4b694340800b08731bcc09099a925',
      ),
    )
    m
  end

  let(:raw_message) do
    # rubocop:disable Style/StringConcatenation, Style/LineEndConcatenation
    "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00" +
      "\x03_25\x04_tcp\x02mx\x08blogreen\03org\x00" +
      "\x00\x34" + # TLSA (52)
      "\x00\x01" + # IN
      "\x00\x00" +
      "\x2a\x30" + # TTL
      "\x00\x23" + # Length
      "\x03" +
      "\x00" +
      "\x01" +
      "\x01\x5a\xd9\xa7\xcb\x61\x43\x17\x33\xb4\x83\xcd\x7e\x15\x5f\x38\xf7\xa7\x76\xfa\x0e\xf7\xf0\xed\x94\xda\x3c\xa8\xd8\x6c\x21\x0a".b +
      "\xc0\x0c".b + # name is re-used
      "\x00\x34" + # TLSA (52)
      "\x00\x01" + # IN
      "\x00\x00" +
      "\x2a\x30" + # TTL
      "\x00\x23" + # Length
      "\x03" +
      "\x01" +
      "\x01" +
      "\xd8\xaa\xc0\xd6\x02\xe5\x53\x21\x36\xff\xb9\xe3\x68\xfb\xc3\xc9\xa7\xa4\xb6\x94\x34\x08\x00\xb0\x87\x31\xbc\xc0\x90\x99\xa9\x25".b
    # rubocop:enable Style/StringConcatenation, Style/LineEndConcatenation
  end

  describe 'when encoding a TLSA record' do
    subject(:encoded_message) { message.encode }

    it 'encodes the TLSA record into the expected DNS message' do
      expect(encoded_message).to eq(raw_message)
    end
  end

  describe 'when decoding a TLSA record' do
    subject(:message) { Resolv::DNS::Message.decode(raw_message) }

    it 'decodes the right number of answers from a DNS message' do
      expect(message.answer.size).to eq(2)
    end

    describe 'the first decoded TLSA record' do
      subject(:record) { message.answer.first[2] } # name, ttl, record

      it 'has the expected certificate usage' do
        expect(record.certificate_usage).to eq(described_class::CertificateUsage::DANE_EE)
      end

      it 'has the expected selector' do
        expect(record.selector).to eq(described_class::Selector::CERT)
      end

      it 'has the expected matching type' do
        expect(record.matching_type).to eq(described_class::MatchingType::SHA2_256)
      end

      it 'has the expected certificate association data' do
        expect(record.certificate_association_data).to eq('015ad9a7cb61431733b483cd7e155f38f7a776fa0ef7f0ed94da3ca8d86c210a')
      end
    end

    describe 'the second decoded TLSA record' do
      subject(:record) { message.answer[1][2] } # name, ttl, record

      it 'has the expected certificate usage' do
        expect(record.certificate_usage).to eq(described_class::CertificateUsage::DANE_EE)
      end

      it 'has the expected selector' do
        expect(record.selector).to eq(described_class::Selector::SPKI)
      end

      it 'has the expected matching type' do
        expect(record.matching_type).to eq(described_class::MatchingType::SHA2_256)
      end

      it 'has the expected certificate association data' do
        expect(record.certificate_association_data).to eq('d8aac0d602e5532136ffb9e368fbc3c9a7a4b694340800b08731bcc09099a925')
      end
    end
  end
end
