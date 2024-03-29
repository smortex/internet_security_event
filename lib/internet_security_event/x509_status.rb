# frozen_string_literal: true

require 'active_support/core_ext/numeric/time'

module InternetSecurityEvent
  class X509Status
    def self.build(object)
      obj = if object.is_a?(OpenSSL::X509::Certificate)
              X509CertificateStatus.new(object)
            elsif object.is_a?(OpenSSL::X509::CRL)
              X509CertificateRevocationListStatus.new(object)
            end
      obj.to_e
    end

    def to_e
      {
        state:       state,
        description: description,
        metric:      metric,
      }
    end

    def renewal_duration
      [validity_duration / 3, 90.days].min
    end

    private

    # Define these method in sub-classes
    # def not_before; end
    # def not_after; end

    def description(name)
      return "#{name} will become valid in #{distance_of_time_in_words_to_now(not_before)}" if not_valid_yet?
      return "#{name} has expired #{distance_of_time_in_words_to_now(not_after)} ago" if expired?

      "#{name} will expire in #{distance_of_time_in_words_to_now(not_after)}"
    end

    def state
      if not_valid_yet? || expired_or_expire_soon?
        'critical'
      elsif expire_soonish?
        'warning'
      else
        'ok'
      end
    end

    def metric
      not_after - now
    end

    def not_valid_yet?
      now < not_before
    end

    def expired_or_expire_soon?
      now + renewal_duration / 3 > not_after
    end

    def expired?
      now > not_after
    end

    def expire_soonish?
      now + 2 * renewal_duration / 3 > not_after
    end

    def validity_duration
      not_after - not_before
    end

    def now
      Now.instance.now
    end

    # Stolen from ActionView, to avoid pulling a lot of dependencies
    def distance_of_time_in_words_to_now(to_time) # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
      distance_in_seconds = (to_time - now).round.abs
      distance_in_minutes = distance_in_seconds / 60

      case distance_in_minutes
      when 0                then 'less than 1 minute'
      when 1...45           then pluralize_string('%d minute', distance_in_minutes)
      when 45...1440        then pluralize_string('about %d hour', (distance_in_minutes.to_f / 60.0).round)
        # 24 hours up to 30 days
      when 1440...43_200    then pluralize_string('%d day', (distance_in_minutes.to_f / 1440.0).round)
        # 30 days up to 60 days
      when 43_200...86_400  then pluralize_string('about %d month', (distance_in_minutes.to_f / 43_200.0).round)
        # 60 days up to 365 days
      when 86_400...525_600 then pluralize_string('%d month', (distance_in_minutes.to_f / 43_200.0).round)
      else
        pluralize_string('about %d year', (distance_in_minutes.to_f / 525_600.0).round)
      end
    end

    def pluralize_string(string, number)
      format(string, number) + (number == 1 ? '' : 's')
    end
  end
end
