# Match capture deadline regressions

From the repository root on macOS with Xcode command-line tools:

```sh
python3 references/authplugin-research/match-deadline-tests/run.py
```

The default runs native, x86_64, and native ASan/UBSan variants. Apple silicon needs Rosetta for the x86_64 variant. Use `--mode native`, `--mode x86`, or `--mode sanitizer` to select one. Generated sources and binaries live in a temporary directory and are removed afterward.

## Test coverage (27 cases per variant)

- Capture (13): short touch; success; repeated low-quality rejection with fresh release/ready state; already-expired deadline with zero reads; late frame; late successful feature extraction; cancellation during feature extraction; cancellation during reading; I/O failure; late I/O failure preserving its error; shared budget across retries; reader wrapper; capture wrapper.
- Provider retry (9): rejection then success; four rejections then success; five-rejection exhaustion; cancellation; rejection then cancellation; timeout; device fault; allocation fault; external stop.
- Post-match guard (5): in-budget work; matcher reaching deadline; lock wait reaching deadline; combined work reaching deadline; combined work just before deadline.
