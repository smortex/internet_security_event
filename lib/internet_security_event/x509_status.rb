# frozen_string_literal: true

require 'action_view'
require 'action_view/helpers'
require 'active_support/core_ext/numeric/time'

module InternetSecurityEvent
  class X509Status
    include ActionView::Helpers::DateHelper

    attr_reader :certificate, :hostname

    def initialize(certificate)
      @certificate = certificate
    end

    def self.build(certificate)
      obj = new(certificate)
      obj.to_e
    end

    def to_e
      {
        state:       state,
        description: description,
        metric:      metric,
        subject:     certificate.subject.to_s,
        issuer:      certificate.issuer.to_s,
        serial:      certificate.serial.to_i,
        not_before:  certificate.not_before.to_s,
        not_after:   certificate.not_after.to_s,
      }
    end

    private

    def description
      return "certificate will become valid in #{distance_of_time_in_words_to_now(certificate.not_before)}" if not_valid_yet?
      return "certificate has expired #{distance_of_time_in_words_to_now(certificate.not_after)} ago" if expired?

      "certificate will expire in #{distance_of_time_in_words_to_now(certificate.not_after)}"
    end

    def state
      if not_valid_yet? || expired_or_expire_soon?
        'critical'
      elsif expire_soonish?
        'warn'
      else
        'ok'
      end
    end

    def metric
      certificate.not_after - now
    end

    def not_valid_yet?
      now < certificate.not_before
    end

    def expired_or_expire_soon?
      now + renewal_duration / 3 > certificate.not_after
    end

    def expired?
      now > certificate.not_after
    end

    def expire_soonish?
      now + 2 * renewal_duration / 3 > certificate.not_after
    end

    def renewal_duration
      [validity_duration / 3, 90.days].min
    end

    def validity_duration
      certificate.not_after - certificate.not_before
    end

    def now
      Now.instance.now
    end
  end
end
