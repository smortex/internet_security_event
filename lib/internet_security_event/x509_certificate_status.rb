# frozen_string_literal: true

require 'internet_security_event/x509_status'

module InternetSecurityEvent
  class X509CertificateStatus < X509Status
    attr_reader :certificate

    def initialize(certificate)
      @certificate = certificate

      super()
    end

    def description
      super('certificate')
    end

    private

    def not_before
      certificate.not_before
    end

    def not_after
      certificate.not_after
    end
  end
end
