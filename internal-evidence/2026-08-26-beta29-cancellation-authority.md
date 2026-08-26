# SharpClaw.Contracts beta29 cancellation authority evidence

The objective was to authenticate the cancellation event for a cross-sidecar peer relay. The plan was to bind cancellation state and time to the host terminal proof, enforce issuance and terminal lifetimes, preserve atomic one-use consumption, and verify invalid events with real session state.

The source adds signed cancellation state and timestamp fields to SidecarHostTerminalAuthority. The canonical terminal authority hash includes both fields. The receiving session requires the Cancelled state, an exact event timestamp, valid issuance order, a current terminal authority, and valid carrier and peer lifetimes before it consumes sequence or reservation state.

The source commit is cfbd267f0e3e14d0ab6ce5fdd029963c886f38e3. It is pushed on main. The source tree was clean before this report, and origin/main matched. The beta29 package candidate is 383430 bytes with SHA-256 85D828F763483D94726E892BC0F00AE380B257EBCE358FFCEF74FCBF78790B34. Its packed DLL SHA-256 is 2D326425C809B0FD2CC90B722ABCA9E1F2BD195CCE64FA45A32422C069B70F0C. Its packed XML SHA-256 is 2AA235F0935AC6C866BC80615C75F405EBC9CEBE0314D566AACB5C58656897E0. Its packed nuspec SHA-256 is A678212574043CF0D52A8C68FA9F084A127FE8C5BC4A45683F4CF2BEA091B718. The nuspec identifies beta29, source cfbd267f0e3e14d0ab6ce5fdd029963c886f38e3, and the canonical repository.

The focused real-session regression passed 1 of 1. The maintained Contracts tests passed 139 of 139. The Gateway tests passed 4 of 4. The exact-head Contracts CI run 32957214468 passed. A fresh package-only consumer restored, built, and ran. It loaded Contracts DLL SHA-256 2D326425C809B0FD2CC90B722ABCA9E1F2BD195CCE64FA45A32422C069B70F0C. Its consumer log SHA-256 is D6F51A91733F0CC57643079480754F7DE50302E2C6BCA912E7F8A75ED7C202C9.

The candidate remains unpublished. Known warnings include NU1903 for System.Security.Cryptography.Xml 10.0.7 and existing XML documentation warnings. No credentials, temporary configurations, archives, logs, caches, or generated files are in the repository. The next bounded turn is Overwatch review.
