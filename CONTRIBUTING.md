# Contributing

Contributions and reports are welcome. Archx is an unaudited prototype; no release or response-time commitment is currently made. Please use synthetic data in issues, tests, logs and examples. Do not publish secrets, raw device identifiers or exploit details. Follow [SECURITY.md](SECURITY.md) for suspected vulnerabilities; a verified private reporting channel is not yet established, so do not post sensitive reports publicly.

For code changes, describe the problem and scope, keep changes reviewable, and run the relevant tests. Linux contributors can run `./test.sh`; the [release checklist](Docs/Guides/Release.md) describes optional native, browser and proxy tests and their dependencies. Tests requiring credentials or special hardware should be clearly identified and should not depend on secrets in untrusted pull requests. Maintainers may request changes, and there is no guarantee a contribution will be accepted or supported.

Project-owned code is licensed under [0BSD](LICENSE), chosen by the project owner. When contributing, submit only material you have the right to contribute under that license; identify any third-party material and its separate terms. The project license does not override third-party licenses. This guidance is not an additional condition on use of already-licensed project code.
