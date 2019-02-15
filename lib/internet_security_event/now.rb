# frozen_string_literal: true

require 'singleton'

module InternetSecurityEvent
  class Now
    include Singleton

    def initialize
      @now = Time.at(Time.now.to_i)
    end

    attr_reader :now
  end
end
