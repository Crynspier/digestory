# Contributing to Digestory

Digestory is a small protocol implementation. Changes should stay focused on correctness, interoperability, security, and maintainability.

## Before changing behavior

Check the relevant RFC 7616 rules, existing tests, the legacy compatibility behavior, and at least one independent implementation when practical.

For protocol or parser changes, add a regression test that demonstrates the behavior being changed.

## Running the test suite

```sh
rake test
rake package
```

The integration suite may use the locally installed `curl` command when available.

Before a release, the complete GitHub Actions matrix and the release artifact build should be green.

## Pull requests

Keep pull requests narrow. Describe:

- the behavior being changed;
- the compatibility or security reason;
- the tests added or updated;
- any RFC or interoperability considerations.

Do not include real credentials or private authentication headers in tests, issues, or pull requests.
