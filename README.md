# InternetSecurityEvent

[![Build Status](https://travis-ci.com/smortex/internet_security_event.svg?branch=master)](https://travis-ci.com/smortex/internet_security_event)
[![Maintainability](https://api.codeclimate.com/v1/badges/bc64fb4f1c1088c15b8c/maintainability)](https://codeclimate.com/github/smortex/internet_security_event/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/bc64fb4f1c1088c15b8c/test_coverage)](https://codeclimate.com/github/smortex/internet_security_event/test_coverage)

Build events describing the status of various internet services

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'internet_security_event'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install internet_security_event

## Usage

This gem can generate events about:

* `TLSStatus` — Status of a TLS connexions (combining the status of the X.509
  certificate and the validity of the hostname hostname);
* `X509Status` — Status of an X.509 certificates.

Usage is basically:

```ruby

certificate = OpenSSL::X509::Certificate.new(...)

event = InternetSecurityEvent::X509Status.build(certificate)

event[:state]       #=> 'ok', 'warn', 'critical'
event[:description] #=> Human readable state
event[:metric]      #=> an optional Float
```

With just a bit more context (e.g. setting `:host` and `:service`), these
events are tailored to be send to [Riemann](http://riemann.io/).

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run
`rake spec` to run the tests. You can also run `bin/console` for an interactive
prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To
release a new version, update the version number in `version.rb`, and then run
`bundle exec rake release`, which will create a git tag for the version, push
git commits and tags, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/smortex/internet_security_event. This project is intended to
be a safe, welcoming space for collaboration, and contributors are expected to
adhere to the [Contributor Covenant](http://contributor-covenant.org) code of
conduct.

1. Fork it (https://github.com/smortex/internet_security_event/fork)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## License

The gem is available as open source under the terms of the [MIT
License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the InternetSecurityEvent project’s codebases, issue
trackers, chat rooms and mailing lists is expected to follow the [code of
conduct](https://github.com/smortex/internet_security_event/blob/master/CODE_OF_CONDUCT.md).
