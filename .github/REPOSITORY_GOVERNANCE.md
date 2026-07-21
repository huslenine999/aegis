# Repository governance settings

The following controls live in GitHub settings and cannot be guaranteed by files
in the repository. Capture screenshots or API exports after configuring them.

- Protect the default branch and release branches against force-push and deletion.
- Require pull requests, two approvals, CODEOWNERS approval and conversation resolution.
- Dismiss stale approvals when security-sensitive files change.
- Require the security pipeline, action E2E and dependency review checks.
- Require signed commits or vigilant-mode verification for maintainers.
- Restrict workflow changes to CODEOWNERS and disable unapproved third-party Actions.
- Enable secret scanning, push protection, Dependabot alerts and private reporting.
- Create a `production-release` environment with at least one reviewer who did
  not author the release and no administrator bypass.
- Restrict tag creation matching `v*` and container package deletion.
- Review deploy keys, GitHub Apps, Actions permissions and organization audit logs quarterly.

Record the reviewer, review date and exported settings digest in the release
evidence. A checklist without configured repository rules is not an implemented control.
