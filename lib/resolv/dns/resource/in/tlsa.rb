# frozen_string_literal: true

class Resolv
  class DNS
    class Resource
      module IN
        class TLSA
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

          def initialize(data)
            @certificate_usage, @selector, @matching_type, @certificate_association_data = data.unpack('CCCH*')
          end

          attr_reader :certificate_usage, :selector, :matching_type, :certificate_association_data

          def end_entity?
            [CertificateUsage::PKIX_EE, CertificateUsage::DANE_EE].include?(certificate_usage)
          end
        end
      end
    end
  end
end
