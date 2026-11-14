# Match capture deadline regressions

From the repository root on macOS with Xcode command-line tools:

```sh
python3 references/authplugin-research/match-deadline-tests/run.py
```

The default runs native, x86_64, and native ASan/UBSan variants. Apple silicon needs Rosetta for the x86_64 variant. Use `--mode native`, `--mode x86`, or `--mode sanitizer` to select one. Generated sources and binaries live in a temporary directory and are removed afterward.

The runner extracts the current production capture function, compatibility wrappers, provider retry loop, and post-matcher deadline guard. Changed source anchors fail explicitly rather than silently running a stale copy. Templates supply fake clocks, frame readers, feature extraction, and Objective-C collaborators. No sensor, broker, policy, system service, or user catalog is opened.

## 27 cases per variant

- Capture (13): short touch; success; repeated low-quality rejection with fresh release/ready state; already-expired deadline with zero reads; late frame; late successful feature extraction; cancellation during feature extraction; cancellation during reading; I/O failure; late I/O failure preserving its error; shared budget across retries; reader wrapper; capture wrapper.
- Provider retry (9): rejection then success; four rejections then success; five-rejection exhaustion; cancellation; rejection then cancellation; timeout; device fault; allocation fault; external stop. Every capture call must receive the same deadline despite clock advancement.
- Post-match guard (5): in-budget work; matcher reaching deadline; lock wait reaching deadline; combined work reaching deadline; combined work just before deadline.

These are source-extracted unit tests, not a complete hardware or Settings UI integration test. The post-match tests advance a fake clock to represent matching/lock delay; they do not exercise real thread contention. No wall-clock reads occur in the extracted capture path. The deadline cannot interrupt synchronous USB, a lock wait, or a broker call already underway. Re-press UI feedback and all possible low-quality inputs remain unverified.
