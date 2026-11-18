# Settings late-boundary candidate

This candidate is built offline. A successful build is not evidence of native Settings enrollment.

## Why the boundary changed

The Settings method slot at image + 0x78be8 belongs to its DATA chained-fixup page.
Apple dyld 1286.10 `Loader::setUpPageInLinking` can register that DATA range using
the original file descriptor. An earlier private write can therefore be lost.
This is a source-supported failure mechanism, not proof of which path a prior live process used.

The existing pinned `disablePageInLinking` call in `runAllInitializersForMain`
follows the mapping/fixup setup and precedes libSystem and ordinary image initializers.
It does not force all lazy pages to be fixed immediately. The candidate reads the method page
and accepts only completely relocated metadata; chained metadata is rejected.

Only the UINT64_MAX call with the exact cached-dyld caller profile is accepted.
The candidate cache base comes from the validated dyld VM base minus 0x1b28000.
`inspectKnownBase` independently validates the cache header, UUID, mapping table,
BiometricKit image/code pins, and repeated cold-state reads. The original process,
main-thread, audit-session and generation checks remain in place. The sentinel is
never treated as a readable user address.

PrebuiltObjC can canonicalize method-list name pointers before this boundary.
The slot, types and implementation pointers stay exactly pinned. Selector names
must match complete NUL-terminated strings in a read-only mapping within the
validated main TEXT or shared-cache region. Canonical pointers in other app images
are conservatively rejected. This does not rewrite selector tables or method caches.

Sources:
- https://github.com/apple-oss-distributions/dyld/blob/dyld-1286.10/dyld/Loader.cpp
- https://github.com/apple-oss-distributions/dyld/blob/dyld-1286.10/dyld/DyldAPIs.cpp
- Existing exact cache capture: `../agent-integration-candidate/early-boundary-observation/cached-dyld-provenance.json`

## Ordinary-user diagnostics

Read `ioreg -r -c ELANNativeProbe -l -w 0`. No root controller is required.
The startup callback updates atomic scalar state; registry values are materialized
when queried, outside that callback. Existing SYSLOG calls remain, but successful
unified-log retrieval is not assumed.

Properties:
- SettingsStartupEnabled: hook route published.
- SettingsStartupAttempts: saturating number of exact-identity callbacks.
- SettingsStartupRouted: saturating count of Routed results, not enrollment results.
- SettingsStartupDiagnostic: last scalar record. Concurrent properties can represent
  adjacent events; they are not a single transactional snapshot.

Diagnostic bits (unsigned 64-bit integer):
- 0..7 event: 0 none, 1 audit rejected, 2 API unavailable, 3 admission rejected, 4 route returned.
- 8..15 admission stage (`StartupAdmission::Stage`).
- 16..23 caller stage (`CallerEvidence::Stage`).
- 24..31 Settings sample stage (`SettingsSample::Stage`).
- 32..39 outer sample stage (`CurrentCopyinSample::Stage`).
- 40..47 route result: 0 skipped, 1 routed, 2 restored, 3 incomplete, 255 not called.
- 48 jointly cold, 49 accepted, 50 matched late boundary.
- 51..55 hardware gate stage: 0 none, 1 arguments, 2 metadata read, 3 relocation,
  4 metadata pins, 5 private slot, 6 write, 7 route, 8 restore, 9 complete, 10 selector strings.
- 56..63 schema = 1.

No pointers, identifiers, authentication contexts, password data or biometric data
are recorded. Zero attempts does not prove the process never executed; an earlier
identity or listener predicate can reject it before recording.

## Verification scope

The build runs policy, real-reader composition, fault-injection, routing/rollback,
and diagnostic concurrency tests under ASan/UBSan. The late composition fixture
uses 174 actual copies and injects a failure at every read. It also rejects a warm
Settings state, warm BiometricKit state, wrong cache UUID, non-main thread and
changed generation. VM query integration is compiled, not runtime-verified.

Do not run the historical first-install script for an upgrade. An approved update
must back up and replace only the existing automatic-settings bundle, preserving
EFI configuration, other drivers and the ordinary-user service. Reboot is required
to run a changed kernel; do not hot-unload or patch the running driver.

## Xiaomi R3 follow-up on 24H32

Boot 10750EB9-C650-42C6-B0CF-D03D24622F81 reported one Settings attempt, no route, and
diagnostic 0x0100ff0000040403. The loaded R3 reached the caller stack check.
In an isolated child using the same Intel Settings and cached dyld images, the return
offsets matched but the first frame step was 25,776 bytes. The 4 KiB step limit
rejected it. R4 accepts up to 32 KiB for that step at the late boundary and keeps the
4 KiB limit for the following step. The read count and exact return offsets stay fixed.
The successful child run included dyld fixups, the real Settings hardware method, and
the installed ELAN service. See `evidence/elan-0c1a/native-settings-resume-20261114/settings-r4-stack-24H32.json`
for the comparison and the remaining native UI test.
