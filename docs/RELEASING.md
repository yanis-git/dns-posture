# Release setup

The public GitHub repository is `yanis-git/dns-posture`. Release tags are `vX.Y.Z` or a SemVer prerelease. The tag must exactly match `package.json`. Stable releases publish to `latest`; prereleases publish to `next`.

First installation uses the maintainer's personal npm account. Run `npm login` locally without sharing credentials. A first personal-account bootstrap prerelease may be necessary to create the package settings. It is not the provenance-bearing stable release.

In npm package settings, configure a GitHub Actions trusted publisher:

- Owner: `yanis-git`
- Repository: `dns-posture`
- Workflow: `release.yml`
- Environment: empty
- Allow direct `npm publish`

Then push the matching release tag. `.github/workflows/release.yml` runs Node 22.14/24/26 tests, lint, secret scanning, tag/version and tracked-data checks, extracts and verifies the npm archive, publishes the verified tarball using OIDC/provenance, and creates the GitHub release. No long-lived npm token is stored in GitHub. A workflow dispatch must target the release tag, not `main`.

After publication, verify `npx --yes dns-posture@1.0.0 --version` from a clean directory/cache and inspect the registry's provenance attestations. A green build alone does not prove publication.

[Official npm trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/) explains prerequisites and the external trust association.
