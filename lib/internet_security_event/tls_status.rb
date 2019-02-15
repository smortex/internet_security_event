# frozen_string_literal: true

require 'internet_security_event/x509_status'

module InternetSecurityEvent
  class TLSStatus < X509Status
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

      hostname_match_subject? || hostname_match_subject_alternative_name?
    end

    def hostname_match_subject?
      common_name == hostname
    end

    def hostname_match_subject_alternative_name?
      return false unless certificate

      san = certificate.extensions.select { |ext| ext.oid == 'subjectAltName' }.first
      return san.value.split(', ').map { |name| name.sub(/\ADNS:/, '') }.include?(hostname) if san

      false
    end

    def common_name
      certificate.subject.to_a.select { |data| data[0] == 'CN' }.map { |data| data[1] }.first if certificate
    end
  end
end
