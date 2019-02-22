# frozen_string_literal: true

require 'resolv'

module InternetSecurityEvent
  class TLSAStatus
    attr_reader :record, :certificate

    def initialize(record, certificate)
      @record = record
      @certificate = certificate

      @resolv = Resolv::DNS.new
    end

    def self.build(record, certificate)
      obj = new(record, certificate)
      obj.to_e
    end

    def to_e
      {
        state:       state,
        description: description,
      }
    end

    def certificate_association_data(selector, matching_type)
      certificate_association_data_digest(certificate_association_data_certificate_bytes(selector), matching_type)
    end

    def certificate_match_tlsa_record?
      certificate_association_data(record.selector, record.matching_type) == record.certificate_association_data
    end

    private

    def certificate_association_data_certificate_bytes(selector)
      case selector
      when Resolv::DNS::Resource::IN::TLSA::Selector::CERT
        certificate.to_der
      when Resolv::DNS::Resource::IN::TLSA::Selector::SPKI
        certificate.public_key.to_der
      end
    end

    def certificate_association_data_digest(bytes, matching_type)
      case matching_type
      when Resolv::DNS::Resource::IN::TLSA::MatchingType::FULL
        bytes.unpack1('H*')
      when Resolv::DNS::Resource::IN::TLSA::MatchingType::SHA2_256
        Digest::SHA256.hexdigest(bytes)
      when Resolv::DNS::Resource::IN::TLSA::MatchingType::SHA2_512
        Digest::SHA512.hexdigest(bytes)
      end
    end

    def state
      return 'critical' unless record

      return nil unless record.end_entity?

      return 'ok' if certificate_match_tlsa_record?

      'critical'
    end

    def description
      if record.end_entity?
        if certificate_match_tlsa_record?
          'certificate match TLSA record'
        else
          'certificate does not match TLSA record'
        end
      else
        # FIXME: For now, we only check the certificate, not the CA
        'Unsupported certificate usage'
      end
    end
  end
end
