# AEGIS GitHub IP SHIELD

Runs on pushes, pull requests, manual dispatches and weekly. Records commit/tree IDs, refs, tracked file paths, Git blob IDs and SHA-256 fingerprints (up to 25,000 files), plus up to 500 commit metadata entries with email hashed. Uploads JSON + checksum artifacts (90-day retention); non-PR runs also preserve versioned snapshots in `ip-shield-ledger`.

Requires Actions enabled and a workflow token allowed to write contents. Repository/org rules may block ledger writes.

Limits: commit author/time are declared metadata, not verified identity or trusted time. Hashes identify bytes, not authorship, originality, ownership or infringement. Source contents are not included. The ledger branch is versioned, not immutable. Third-party and joint contributions retain their rights/licenses. This workflow does not register IP, prevent copying or revoke third-party rights, and covers only this repository and triggered refs.
