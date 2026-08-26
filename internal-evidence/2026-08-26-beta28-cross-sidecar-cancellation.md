# SharpClaw.Contracts beta28 cross-sidecar cancellation evidence

The objective was to consume an authenticated cross-sidecar peer relay when cancellation occurs before terminal import. The plan was to add one session-owned cancellation contract, consume the receiving sequence atomically, preserve one-use and budget rules, and prove mutation, replay, concurrency, and later-use behavior with two real sessions.

The source change adds SidecarCrossSidecarActionEntryPeerCancellation and the receiving-session consumption operation. The operation validates the host terminal proof, source and peer lineage, binding generation, payload, carrier lifetime, sequence, nonce, replay state, and receiving-root reservation before state changes. It consumes the relay without creating an executable child call. Cleanup drains peer work after local lock release.

The source commit is 7e6351f351bdbcae7a338f248a605ce9464cb1d6. The commit is pushed on main, origin/main matches, and git diff --check passes. The unpublished beta28 package has SHA-256 3369D76FA748034BBAB4E4E8D20E5899FC8D46399FB682E81FF6D3E84DC5B346. Its packed DLL SHA-256 is 927ED4A07860DC1785EB75D6C253997E71E88C3CDE4A9B132A4B5C0728C9A428. Its packed XML SHA-256 is 2AA235F0935AC6C866BC80615C75F405EBC9CEBE0314D566AACB5C58656897E0. Its package metadata identifies beta28, source commit 7e6351f351bdbcae7a338f248a605ce9464cb1d6, and the canonical repository.

The focused cancellation regression passed 1 of 1. The maintained Contracts tests passed 139 of 139. The Gateway tests passed 4 of 4. The exact-head Contracts CI run 32955283738 passed. A package-only consumer restored, built, and ran with the local package. It loaded Contracts DLL SHA-256 927ED4A07860DC1785EB75D6C253997E71E88C3CDE4A9B132A4B5C0728C9A428.

The candidate remains unpublished. No source change is required after the measured result. Known warnings include NU1903 for System.Security.Cryptography.Xml 10.0.7 in the existing dependency set. The next bounded turn is Overwatch review of this source and package candidate.
