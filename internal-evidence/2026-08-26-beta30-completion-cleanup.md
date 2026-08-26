Objective

Prepare SharpClaw.Contracts 0.5.0-beta.30 with bounded cleanup for rejected call completion. Preserve retryable active-descendant rejection and release known non-retryable call state atomically.

Plan

Update the session completion state machine. Add focused real-session regressions. Run the complete Contracts and Gateway suites. Pack and inspect the unpublished package. Run a package-only consumer and record the source and package evidence.

Work

Commit 32ea9b3fc6b438da7dd58d5b6bfb6f6fdd587c8c adds ReleaseCompletedCallState. Active descendants remain retryable and preserve state. Terminal-count rejection returns its original code and message, then removes call identity, payload, entry context, terminal state, receipts, continuations, budget state, descendants, and in-flight state. The outer carrier remains completable for its one failed completion.

Evidence

The focused Contracts gate passed 3/3 tests with zero skips. Its TRX SHA-256 is 7EC04F5B11C706024036429552915F66E3D565E58C25B4872EEAE2786740D863. The complete Contracts gate passed 141/141 tests with zero skips. Its TRX SHA-256 is D764B2E87893D034288F2E4300241183E7CA78C49F7A1F3BFACF0BAD923B65F1. The Gateway gate passed 4/4 tests with zero skips. Its TRX SHA-256 is 41E28008650E3D4FBB46BFDA2FE95832C132AB10FBAA6B577C18207A5087FB66.

The immutable package is D:\temp\SharpClaw.Contracts\completion-beta30-repair\package-final\SharpClaw.Contracts.0.5.0-beta.30.nupkg. Its length is 383485 bytes. Its SHA-256 is D4BD1AD59F24909E938FBF18237C69E665CDF567742CE7815B924D62580E2AA7. The packed DLL SHA-256 is 07467E5B5704120C0FB3826A9EA7DB3384D3301BB04BF7E96773B7A3C7158B7F. The packed XML SHA-256 is 2AA235F0935AC6C866BC80615C75F405EBC9CEBE0314D566AACB5C58656897E0. The packed nuspec SHA-256 is 57C12C0E1A001633009ED498CA35B4E077F5E69731871FF7D9758DCC6375648B. The nuspec records beta30, source 32ea9b3fc6b438da7dd58d5b6bfb6f6fdd587c8c, and the canonical repository.

The fresh package-only consumer restored beta30 and beta23 from task-local package sources. It built successfully and completed one typed action. It loaded Contracts DLL SHA-256 07467E5B5704120C0FB3826A9EA7DB3384D3301BB04BF7E96773B7A3C7158B7F and Core DLL SHA-256 CA7BB58BF2144D698BC5D877060831BC8C7895FF6676B583C787B06513A97868.

Result

The Contracts source and package candidate satisfy the local completion cleanup objective. No package was published. The Core source now exact-pins Contracts beta30.

Diff disposition

The source diff contains only the completion cleanup, its focused tests, and the beta30 package identity. This report contains sanitized evidence only. It contains no credentials, archives, caches, logs, or temporary configurations.

Commit disposition

The source commit is pushed to origin/main. The report commit will be pushed after this report is added. The source tree will be checked for clean status and equal local and remote heads.

Risks

The build reports existing NU1903 warnings for System.Security.Cryptography.Xml 10.0.7. The maintained tests report existing XML documentation warnings and one nullable test warning. No new source warning was introduced by this correction.

Next bounded turn

Run or confirm exact-head CI for the report head. Verify the Core package and evidence commit. Send the consolidated unpublished package handoff to Codex Overwatch. Keep publication blocked.
