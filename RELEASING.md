# Releasing Anatoly

1. Update `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, installer default VERSION and the
   versioned README/Exegol install URLs together. Recheck dated advisory policy sources.
2. Run formatting, clippy, all loopback tests and `bash scripts/test-installer.sh`.
3. Merge the release changes through a reviewed pull request after CI succeeds.
4. Tag that commit `vX.Y.Z` and push the tag. The release workflow checks that the tag
   matches the Cargo package version; non-stable tags are rejected.
5. The workflow tests each platform, builds native Linux x86_64/ARM64 and Windows x86_64
   archives, then publishes all assets and SHA256SUMS together only after all jobs pass.
6. Download the published release, verify hashes and run a zero-request `doctor` check.
   Exercise Linux installation in a temporary directory and verify `--version` before
   announcing it. Keep public usage claims limited to validated platforms.

CI and build jobs have read-only repository access. Only the final release job can
write release assets. Third-party action references are pinned to commit SHAs.
Releases are not automatically published to crates.io or added to Exegol images.
