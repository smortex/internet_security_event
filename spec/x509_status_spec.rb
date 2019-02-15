# frozen_string_literal: true

require_relative 'shared_examples'

RSpec.describe InternetSecurityEvent::X509Status do
  subject do
    InternetSecurityEvent::X509Status.new(certificate)
  end

  include_examples 'with an X.509 certificate'
end
