Objective

Prepare SharpClaw.Contracts 0.5.0-beta.30 with bounded cleanup for rejected call completion. Preserve retryable active-descendant rejection and release known non-retryable call state atomically.

Plan

Update the session completion state machine. Add focused real-session regressions. Run the complete Contracts and Gateway suites. Pack and inspect the unpublished package. Run a package-only consumer through the Core package gate.

Work

Commit 9d06cf799dbb3bd65111e8036101bd1632824cab moves the active-descendant check before terminal-count validation. Invalid terminal counts now call ReleaseCompletedCallState and return the original code and message. The cleanup removes the call identity, payload, entry context, terminal state, receipts, continuations, budget state, descendants, replay state, and in-flight state. The outer carrier remains completable for its one failed completion. CI commit 9c08e846066229c9018e11e26e7f75fa61ddd7d0 enables manual exact-head execution without changing production code.

Evidence

The focused completion gate passed 6/6 tests with zero skips. Its TRX SHA-256 is FEFBFE908C05B244D04A965880A7CDB81CF6BECC250BF61AF5B4B3218AC82FC8. The complete Contracts gate passed 144/144 tests with zero skips. Its TRX SHA-256 is 7B107EABB13B75403496DEC882FAE7C0E9AA0D3AB9BB6E532B23AFE4EAE66C53. The Gateway gate passed 4/4 tests with zero skips. Its TRX SHA-256 is A7E1D27FA7E2C7A185D3F28EBEEFD5C2CB2876375F9E8C169D17040E17052B76. Exact-head Contracts CI run 32988759792 passed for 9c08e846066229c9018e11e26e7f75fa61ddd7d0.

The replacement package is D:\temp\SharpClaw.Contracts\completion-beta30-repair-v3-final\package\SharpClaw.Contracts.0.5.0-beta.30.nupkg. Its length is 383503 bytes. Its SHA-256 is 7F8E62CC72EC47B1D9A1A3F54DB51345475C212B59BB7E1A77966BB80F625140. The packed DLL SHA-256 is DF2ADE2596BE3A54482E7DFDB29560543CD3EA0D74C64FC100F767CCB1853A85. The packed XML SHA-256 is 2AA235F0935AC6C866BC80615C75F405EBC9CEBE0314D566AACB5C58656897E0. The packed nuspec SHA-256 is F21564584345C1E5ECE0D78193F5D6BD4A861F2E5F68673F882258162A7020D9. The nuspec records beta30, source 9c08e846066229c9018e11e26e7f75fa61ddd7d0, and the canonical repository.

The fresh Core package-only consumer restored beta30 and beta23 from task-local package sources. It built successfully and completed one typed action. It loaded Contracts DLL SHA-256 DF2ADE2596BE3A54482E7DFDB29560543CD3EA0D74C64FC100F767CCB1853A85 and Core DLL SHA-256 9638942E3AD077DF041878F736C2E7416E46397240E8C4BE9C6E178A0C85D2D1. The consumer run log SHA-256 is not stored in this tracked report.

Result

The local Contracts completion, Gateway, package, consumer, and exact-head CI gates pass. No package was published.

Diff disposition

The source diff contains only invalid completion cleanup and its focused tests. The CI commit changes only workflow dispatch support. This report contains sanitized evidence only. It contains no credentials, archives, caches, logs, or temporary configurations.

Commit disposition

The source and CI commits are pushed to origin/main. This report will be pushed in a separate documentation commit. The working tree will be checked for clean status and equal local and remote heads.

Risks

The builds report existing NU1903 advisories for System.Security.Cryptography.Xml 10.0.7. Contracts also reports existing XML documentation warnings and one nullable test warning. The Core CI run reports existing XML documentation annotations, one nullable warning, and Node.js 20 action deprecation annotations.

Next bounded turn

Update the Core report with its final source and package identities. Commit and push both sanitized reports. Send the consolidated unpublished package handoff to Codex Overwatch. Keep publication blocked.
