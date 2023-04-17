# frozen_string_literal: true

require 'internet_security_event/x509_certificate_status'

module InternetSecurityEvent
  class TLSStatus < X509CertificateStatus
    attr_reader :hostname

    def initialize(hostname, certificate)
      @hostname = hostname
      super(certificate)
    end

    def self.build(hostname, certificate)
      obj = new(hostname, certificate)
      obj.to_e
    end

    private

    def description
      return 'certificate subject does not match hostname' unless hostname_is_valid_for_this_certificate?

      super
    end

    def state
      if !hostname_is_valid_for_this_certificate?
        'critical'
      else
        super
      end
    end

    def hostname_is_valid_for_this_certificate?
      return true if hostname.nil?

      OpenSSL::SSL.verify_certificate_identity(certificate, hostname)
    end
  end
end
