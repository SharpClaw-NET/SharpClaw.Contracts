# SharpClaw.Contracts beta29 publication evidence

The objective was to publish the accepted Contracts beta29 archive to NuGet.org and the canonical SharpClaw-NET GitHub Packages feed. The plan was to verify the immutable archive, prove both target versions were absent, publish Contracts before Core, and complete feed-specific consumer checks.

The exact Contracts archive was verified before publication. It has length 383492 bytes and SHA-256 678F5D5B395C0EF950910886C9695CF174C1B83363E6D5331ED4213146C1058B. Its packed DLL SHA-256 is 65817E8ACE02EF0487069E6C2721F5255B925868B7D155C8A6CB87A94B07CCE6. Its packed XML SHA-256 is 2AA235F0935AC6C866BC80615C75F405EBC9CEBE0314D566AACB5C58656897E0. Its packed nuspec SHA-256 is E36E3A4D68E67F91F13216956E845CA1CA1F24355AFDF1851104214EC8D98DE4. The package identifies source 45a9d9ceac876373b111e1abc481b41d72de50d4 and the canonical repository.

The target version was absent from both feeds before the push. The package was published first to NuGet.org and then to the canonical SharpClaw-NET GitHub Packages feed. The GitHub download is 383492 bytes with SHA-256 678F5D5B395C0EF950910886C9695CF174C1B83363E6D5331ED4213146C1058B. The NuGet.org normalized download is 396576 bytes with SHA-256 885B10510C43C5DAA09A12DD024FCAC8FF76AD4C3CF5E00E114A8E234A78CE0D. Both downloads contain the accepted DLL, XML, and nuspec hashes. The nuspec keeps beta29, source 45a9d9ceac876373b111e1abc481b41d72de50d4, and the canonical repository.

A fresh NuGet.org-only consumer restored, built, and ran with Contracts beta29 and Core beta22. A fresh GitHub-mapped consumer also restored, built, and ran. Both loaded Contracts DLL SHA-256 65817E8ACE02EF0487069E6C2721F5255B925868B7D155C8A6CB87A94B07CCE6. The consumer log SHA-256 is D7AEC64A3B8956037BF16CEC60C016819B79C51DAF6011872B85333FB7C958B0.

The result improves the objective. The Contracts publication is complete. No credential, temporary configuration, archive, cache, or log is tracked. The next bounded turn is Core publication closeout.
