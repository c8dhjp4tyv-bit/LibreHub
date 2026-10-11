# Rebuild verification

Stop the API first (the supervisor data lock protects operator mutation):

```bash
LIBREHUB_DATA_DIR=data ./target/debug/librehub-admin \
  builds verify-reproducibility BUILD_UUID
```

The trusted build helper sets `SOURCE_DATE_EPOCH=1` and explicitly overrides
Flatpak-builder's manifest-mtime-derived epoch. This is a normalization input,
not a claim about the source commit date; it is recorded in build environment
parameters. A clean image probe verifies the helper digest against the supervisor
implementation before accepting its environment evidence.

The operator command retains the original build and records a new build UUID,
original snapshot/provenance, selected image content ID, runtime/SDK and isolation
configuration. It verifies the retained snapshot and requires the second actual
execution environment to equal the original. It never resolves the current branch
head for a rebuild or overwrites the original artifact. Missing immutable source,
environment, or mutable declared dependencies yield `unsupported`. Execution,
environment or comparison failures yield `inconclusive`.

Comparison imports both verified pre-publication bundles and hashes recursive
OSTree checksum listings of the complete tree. File checksums retain content,
mode, ownership and xattrs; tree listings retain paths and directory structure.
Commit dates, parents, signing and publication metadata are excluded. This is
content equivalence of the Flatpak payload, not byte-identical bundle or final
published commit equivalence. Listings have M2's 1 MiB subprocess-output cap; a
larger comparison is inconclusive. Differing content yields `non_reproducible`.

Each attempt is appended durably, with content digests and a reason. A pre-execution
inconclusive record makes interrupted attempts visible; completion appends the
result rather than deleting history. The public UI reports the latest result
separately from signature trust. Signing does not imply reproducibility.

The real M6 acceptance script builds the Hello shell fixture twice and requires
matching content, then adds a file containing nanosecond time and requires a
visible mismatch. Arbitrary third-party apps can include clocks, random values,
filesystem order, toolchain/build-path effects, network data, generated metadata
or undeclared inputs; a successful fixture rebuild does not prove they reproduce.
