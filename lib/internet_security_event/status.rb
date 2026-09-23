# frozen_string_literal: true

module InternetSecurityEvent
  class Status
    def to_e
      res = {
        state:       state,
        description: description,
      }
      res[:metric] = metric if respond_to?(:metric)
      res
    end
  end
end
