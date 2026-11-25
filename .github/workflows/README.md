# GitHub workflows

`ci.yml` runs the Linux suite on ordinary pushes and pull requests with read-only contents permission and no persisted checkout credentials. Repository branch protection must separately require its job; the workflow alone cannot prevent a merge. `archx-linux-test.yml` is the separate opt-in, write-enabled Linux permissions survey; see `../archx-runner/README.md`. Neither constitutes native Windows/macOS evidence.
