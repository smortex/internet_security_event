# frozen_string_literal: true

class Resolv
  class DNS
    class Resource
      module IN
        class TLSA < Resource
          TypeValue = 52
          ClassValue = IN::ClassValue
          ClassHash[[TypeValue, ClassValue]] = self

          module CertificateUsage
            PKIX_TA = 0
            PKIX_EE = 1
            DANE_TA = 2
            DANE_EE = 3
          end

          module Selector
            CERT = 0
            SPKI = 1
          end

          module MatchingType
            FULL = 0
            SHA2_256 = 1
            SHA2_512 = 2
          end

          def initialize(certificate_usage, selector, matching_type, certificate_association_data)
            super()

            @certificate_usage = certificate_usage.to_int
            @selector = selector.to_int
            @matching_type = matching_type.to_int
            @certificate_association_data = certificate_association_data
          end

          attr_reader :certificate_usage, :selector, :matching_type, :certificate_association_data

          def encode_rdata(msg)
            msg.put_bytes(@certificate_usage)
            msg.put_bytes(@selector)
            msg.put_bytes(@matching_type)
            msg.put_pack('H*', @certificate_association_data)
          end

          def self.decode_rdata(msg)
            certificate_usage, selector, matching_type = msg.get_unpack('ccc')
            certificate_association_data = msg.get_bytes.unpack1('H*')

            new(certificate_usage, selector, matching_type, certificate_association_data)
          end

          def end_entity?
            [CertificateUsage::PKIX_EE, CertificateUsage::DANE_EE].include?(certificate_usage)
          end
        end
      end
    end
  end
end
