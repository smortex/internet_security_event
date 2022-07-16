## [v1.2.1] - 2022-07-15

### Changed
- Emit a `warning` state instead of a `warn` state to match Riemann wording.

## [v1.2.0] - 2019-02-28

### Changed
- Rely on `OpenSSL::SSL.verify_certificate_identity` to check that a certificate
  is valid for the provided hostname.

## [v1.1.0] - 2019-02-21

### Added
- Add basic suport for TLSA events.

## [v1.0.2] - 2019-02-21

### Changed
- Fix checking of TLS hostnames with wildcard certificates.

## [v1.0.1] - 2019-02-18

### Changed
- Improve the way TLS certificates state is computed.

[v1.2.1]: https://github.com/smortex/internet_security_event/compare/v1.2.0...v1.2.1
[v1.2.0]: https://github.com/smortex/internet_security_event/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/smortex/internet_security_event/compare/v1.0.2...v1.1.0
[v1.0.2]: https://github.com/smortex/internet_security_event/compare/v1.0.1...v1.0.2
[v1.0.1]: https://github.com/smortex/internet_security_event/compare/v1.0.0...v1.0.1
