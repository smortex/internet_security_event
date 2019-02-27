# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Rely on `OpenSSL::SSL.verify_certificate_identity` to check that a certificate
  is valid for the provided hostname.

## [1.1.0] - 2019-02-21

### Added
- Add basic suport for TLSA events.

## [1.0.2] - 2019-02-21

### Changed
- Fix checking of TLS hostnames with wildcard certificates.

## [1.0.1] - 2019-02-18

### Changed
- Improve the way TLS certificates state is computed.

[Unreleased]: https://github.com/smortex/internet_security_event/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/smortex/internet_security_event/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/smortex/internet_security_event/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/smortex/internet_security_event/compare/v1.0.0...v1.0.1
