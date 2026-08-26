Objective

Prepare SharpClaw.Contracts 0.5.0-beta.30 with bounded cleanup for rejected call completion. Preserve retryable active-descendant rejection and release known non-retryable call state atomically.

Plan

Update the session completion state machine. Add focused real-session regressions. Run the complete Contracts and Gateway suites. Pack and inspect the unpublished package. Run a package-only consumer through the Core package gate.

Work

Commit 9d06cf799dbb3bd65111e8036101bd1632824cab moves the active-descendant check before terminal-count validation. Invalid terminal counts now call ReleaseCompletedCallState and return the original code and message. The cleanup removes the call identity, payload, entry context, terminal state, receipts, continuations, budget state, descendants, replay state, and in-flight state. The outer carrier remains completable for its one failed completion.

Evidence

The focused completion gate passed 6/6 tests with zero skips. Its TRX SHA-256 is FEFBFE908C05B244D04A965880A7CDB81CF6BECC250BF61AF5B4B3218AC82FC8. The complete Contracts gate passed 144/144 tests with zero skips. Its TRX SHA-256 is 7B107EABB13B75403496DEC882FAE7C0E9AA0D3AB9BB6E532B23AFE4EAE66C53. The Gateway gate passed 4/4 tests with zero skips. Its TRX SHA-256 is A7E1D27FA7E2C7A185D3F28EBEEFD5C2CB2876375F9E8C169D17040E17052B76.

The replacement package is D:\temp\SharpClaw.Contracts\completion-beta30-repair-v2-final\package\SharpClaw.Contracts.0.5.0-beta.30.nupkg. Its length is 383504 bytes. Its SHA-256 is 7A5BF3BC7F941379D457A94C90C23BF58193E8F009B7FD7325525A2A158C68F5. The packed DLL SHA-256 is A7C75B47C11194AF46BF6684C57FBDB38A4075136F4C625DEE2CD6AADD3A6A66. The packed XML SHA-256 is 2AA235F0935AC6C866BC80615C75F405EBC9CEBE0314D566AACB5C58656897E0. The packed nuspec SHA-256 is 9A7CE47A4EF69228C839F43436056DF6C9EE6D9D48D55CA26017B7F00C14C21F. The nuspec records beta30, source 9d06cf799dbb3bd65111e8036101bd1632824cab, and the canonical repository.

The fresh package-only consumer restored beta30 and beta23 from task-local package sources. It built successfully and completed one typed action. It loaded Contracts DLL SHA-256 A7C75B47C11194AF46BF6684C57FBDB38A4075136F4C625DEE2CD6AADD3A6A66 and Core DLL SHA-256 682D0144275DA87195347EFF388139891D3D6FFA8250F1C5F6FFD381CCD32448. The consumer run log SHA-256 is ECBD72A85A52E557D779AAA660DA810C44E82D76AAE90A13F72F5940A3CE8024.

Result

The local Contracts completion and Gateway gates pass. The Core beta23 package aligns to Contracts beta30. No package was published.

Diff disposition

The source diff contains only invalid completion cleanup and its focused tests. This report contains sanitized evidence only. It contains no credentials, archives, caches, logs, or temporary configurations.

Commit disposition

The source commit is pushed to origin/main. The report commit will follow after the Core evidence update. The working tree will be checked for clean status and equal local and remote heads.

Risks

The builds report existing NU1903 advisories for System.Security.Cryptography.Xml 10.0.7. Contracts also reports existing XML documentation warnings and one nullable test warning. Contracts CI has not produced a run for source 9d06cf799dbb3bd65111e8036101bd1632824cab at this point.

Next bounded turn

Record the Core replacement package evidence and report commits. Confirm exact-head CI status. Send the consolidated unpublished package handoff to Codex Overwatch. Keep publication blocked.
