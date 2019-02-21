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
      name_match_patern(hostname, common_name)
    end

    def hostname_match_subject_alternative_name?
      return false unless certificate

      san = certificate.extensions.select { |ext| ext.oid == 'subjectAltName' }.first

      if san
        alt_names = san.value.split(', ').map { |name| name.sub(/\ADNS:/, '') }
        return true if alt_names.any? { |alt_name| name_match_patern(hostname, alt_name) }
      end

      false
    end

    def name_match_patern(hostname, pattern)
      re = Regexp.new('\A' + pattern.split('*').map do |st|
        Regexp.escape(st)
      end.join('[^.]*') + '\z')

      re.match(hostname)
    end

    def common_name
      certificate.subject.to_a.select { |data| data[0] == 'CN' }.map { |data| data[1] }.first if certificate
    end
  end
end
