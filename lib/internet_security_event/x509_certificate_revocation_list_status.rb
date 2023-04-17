# frozen_string_literal: true

require 'internet_security_event/x509_status'

module InternetSecurityEvent
  class X509CertificateRevocationListStatus < X509Status
    attr_reader :crl

    def initialize(crl)
      @crl = crl

      super()
    end

    def description
      super('crl')
    end

    def to_e
      super.merge({
                    issuer:      crl.issuer.to_s,
                    last_update: crl.last_update.to_s,
                    next_update: crl.next_update.to_s,
                  })
    end

    private

    def not_before
      crl.last_update
    end

    def not_after
      crl.next_update
    end
  end
end
