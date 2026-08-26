Objective

Publish the accepted SharpClaw.Contracts beta30 and SharpClaw.Core beta23 archives to NuGet.org and canonical SharpClaw-NET GitHub Packages. Verify both feeds and fresh package consumers.

Publication

The Contracts archive was checked immediately before each push. The accepted local archive is D:\temp\SharpClaw.Contracts\completion-beta30-repair-v3-final\package\SharpClaw.Contracts.0.5.0-beta.30.nupkg. Its length is 383503 bytes and its SHA-256 is 7F8E62CC72EC47B1D9A1A3F54DB51345475C212B59BB7E1A77966BB80F625140. NuGet.org accepted the push with HTTP 201. Canonical GitHub Packages accepted the push with HTTP 200. Duplicate checks returned HTTP 404 on both feeds before publication.

The Core archive was checked immediately before each push. The accepted local archive is D:\temp\SharpClaw.Core\completion-beta23-repair-v3-final\package\SharpClaw.Core.0.5.0-beta.23.nupkg. Its length is 279023 bytes and its SHA-256 is C4FBD44D6EAC7E25F5885205244DB88EB9D10C7279AD41430BDFA49917466165. NuGet.org accepted the push with HTTP 201. Canonical GitHub Packages accepted the push with HTTP 200. Duplicate checks returned HTTP 404 on both feeds before publication.

Feed verification

The GitHub Contracts download is 383503 bytes with SHA-256 7F8E62CC72EC47B1D9A1A3F54DB51345475C212B59BB7E1A77966BB80F625140. The NuGet.org Contracts download is 396587 bytes with normalized SHA-256 6EA9DF275DA262D88FC9378D89E4AA910273F4990F6A0791E8A4ADAFEAB4B4C5. Both contain DLL SHA-256 DF2ADE2596BE3A54482E7DFDB29560543CD3EA0D74C64FC100F767CCB1853A85, XML SHA-256 2AA235F0935AC6C866BC80615C75F405EBC9CEBE0314D566AACB5C58656897E0, and nuspec SHA-256 F21564584345C1E5ECE0D78193F5D6BD4A861F2E5F68673F882258162A7020D9. The nuspec records beta30, source 9c08e846066229c9018e11e26e7f75fa61ddd7d0, and the canonical repository.

The GitHub Core download is 279023 bytes with SHA-256 C4FBD44D6EAC7E25F5885205244DB88EB9D10C7279AD41430BDFA49917466165. The NuGet.org Core download is 292108 bytes with normalized SHA-256 641A5CD5C471939D4C74EE0EA0048945EF1C211AD361870A23F8AB901BEC197F. Both contain DLL SHA-256 9638942E3AD077DF041878F736C2E7416E46397240E8C4BE9C6E178A0C85D2D1, XML SHA-256 FFFCAFF08EBA926AB87A6B71C818175EB328BB37049FABF35F9D505C8DD776FB, and nuspec SHA-256 B80851A593211DC59D3934EC0D7A27D186413FED4899B060590B5645D90F3B9E. The nuspec records beta23, source c5c8953e559f40e9bada0c9bc4f2df0473e6ed27, the canonical repository, and exact Contracts [0.5.0-beta.30].

Consumers

The fresh NuGet.org-only consumer restored both public packages, built, and completed one typed action. It loaded Contracts DLL SHA-256 DF2ADE2596BE3A54482E7DFDB29560543CD3EA0D74C64FC100F767CCB1853A85 and Core DLL SHA-256 9638942E3AD077DF041878F736C2E7416E46397240E8C4BE9C6E178A0C85D2D1. The fresh GitHub-mapped consumer produced the same completed result and hashes.

Result

Both packages are public on the two authorized feeds. The publication closeout is complete. No credentials were saved in configuration or committed.

Risks

Existing NU1903 advisories for System.Security.Cryptography.Xml 10.0.7 remain. Existing XML documentation warnings remain in Contracts and Core. CI also reports existing nullable and Node.js action deprecation annotations.
