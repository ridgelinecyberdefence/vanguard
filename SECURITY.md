# Security Policy

## Reporting a vulnerability

VanGuard is a DFIR tool that runs with high privilege on systems handling sensitive
evidence, so we take security reports seriously and appreciate responsible disclosure.

**Do not open a public issue for a security vulnerability.**

Report it privately by one of these routes:

- Email **security@ridgelinecyber.com** with the details below, or
- Use GitHub's [private vulnerability reporting](https://github.com/ridgelinecyberdefence/vanguard/security/advisories/new)
  (Security tab &rarr; Report a vulnerability).

Please include:

- The version or commit you tested (`vanguard --version`)
- The platform (Windows or Linux) and how VanGuard was run
- A description of the issue and its impact
- Steps to reproduce, and a proof of concept if you have one

## What to expect

- We aim to acknowledge a report within **3 business days**.
- We will confirm the issue, assess severity, and keep you updated as we work on a fix.
- Once a fix is released, we will credit you in the release notes and the changelog
  unless you ask us not to.

## Scope

In scope: the VanGuard binary and its modules in this repository, including credential
handling, evidence integrity (hashing and chain of custody), archive extraction,
remote-execution paths, and report generation.

Out of scope: vulnerabilities in third-party tools VanGuard orchestrates (Velociraptor,
Volatility3, Hayabusa, Chainsaw, Loki, YARA, KAPE, and similar). Report those to their
respective maintainers. If VanGuard invokes one of those tools in an unsafe way, that
is in scope.

## Supported versions

VanGuard is released from `main`. Security fixes land on the latest release. We do not
backport fixes to older tags; upgrade to the current release to receive them.
