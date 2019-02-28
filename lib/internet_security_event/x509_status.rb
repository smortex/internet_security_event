# frozen_string_literal: true

require 'active_support/core_ext/numeric/time'

module InternetSecurityEvent
  class X509Status
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

    def renewal_duration
      [validity_duration / 3, 90.days].min
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

    def validity_duration
      certificate.not_after - certificate.not_before
    end

    def now
      Now.instance.now
    end

    # Stolen from ActionView, to avoid pulling a lot of dependencies
    def distance_of_time_in_words_to_now(to_time)
      distance_in_seconds = (to_time - now).round.abs
      distance_in_minutes = distance_in_seconds / 60

      case distance_in_minutes
      when 0                then 'less than 1 minute'
      when 1...45           then pluralize_string('%d %s', distance_in_minutes, 'minute')
      when 45...1440        then pluralize_string('about %d %s', (distance_in_minutes.to_f / 60.0).round, 'hour')
        # 24 hours up to 30 days
      when 1440...43_200    then pluralize_string('%d %s', (distance_in_minutes.to_f / 1440.0).round, 'day')
        # 30 days up to 60 days
      when 43_200...86_400  then pluralize_string('about %d %s', (distance_in_minutes.to_f / 43_200.0).round, 'month')
        # 60 days up to 365 days
      when 86_400...525_600 then pluralize_string('%d %s', (distance_in_minutes.to_f / 43_200.0).round, 'month')
      else
        pluralize_string('about %d %s', (distance_in_minutes.to_f / 525_600.0).round, 'year')
      end
    end

    def pluralize_string(string, number, word)
      format(string, number, pluralize_word(number, word))
    end

    def pluralize_word(number, word)
      word + (number.abs == 1 ? '' : 's')
    end
  end
end
