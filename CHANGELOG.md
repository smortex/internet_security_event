# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v3.0.0](https://github.com/smortex/internet_security_event/tree/v3.0.0) (2023-04-17)

[Full Changelog](https://github.com/smortex/internet_security_event/compare/v2.0.0...v3.0.0)

**Breaking changes:**

- Add support for verifying CRL [\#4](https://github.com/smortex/internet_security_event/pull/4) ([smortex](https://github.com/smortex))

## [v2.0.0](https://github.com/smortex/internet_security_event/tree/v2.0.0) (2022-07-16)

[Full Changelog](https://github.com/smortex/internet_security_event/compare/v1.2.1...v2.0.0)

**Breaking changes:**

- Bump activesupport to 6.x [\#2](https://github.com/smortex/internet_security_event/pull/2) ([smortex](https://github.com/smortex))

**Merged pull requests:**

- Integrate github\_changelog\_generator [\#1](https://github.com/smortex/internet_security_event/pull/1) ([smortex](https://github.com/smortex))

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


\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
