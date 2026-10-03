# Public Git source integration

`services/source` owns the SourceProvider boundary: revision resolution, immutable
fetch and manifest discovery/snapshot preparation. GitSource supports anonymous
public HTTPS smart-HTTP Git, with github and git provider identities. The provider
field affects identity validation; neither requires a hosting SDK or personal
GitHub credential. Private repositories, SSH, OAuth and GitHub Apps are deferred.

## Network boundary

Repository admission normalizes HTTPS URLs and GitHub repository casing, with one
`.git` suffix. URLs cannot contain credentials, percent escapes, queries, fragments,
custom ports or unsafe path components. file/ssh/local filesystem sources are not
accepted. Localhost/private/link-local/metadata/documentation/reserved addresses
are rejected, including numeric IPv4 aliases and mapped IPv6. DNS is checked again
when connecting; every result must be a permitted public address. The trusted
reqwest client pins these addresses, preserves TLS hostname verification, disables
HTTP redirects and ignores ambient proxies. DNS rebinding cannot change its origin.

Git itself talks only to a short-lived, loopback smart-HTTP relay. This relay has a
random path and accepts exactly `info/refs?service=git-upload-pack` and
`git-upload-pack`, forwarding to the validated pinned origin. Responses must have
the smart-Git content type. Dumb-HTTP fallback and its alternate repository URLs
are refused, preventing Git from following arbitrary provider-supplied URLs.
Redirects/authentication/404/unsupported transport failures are permanent; network
and 5xx/deadline failures get at most three attempts. Errors never expose upstream
bodies, URLs containing secrets or internal paths. HTTP requests/responses are
bounded to 1 MiB/128 MiB, one relay request at a time, with 5-second connect and
120-second operation deadlines.

Git processes have empty environments except explicit safe PATH/HOME/Git settings.
System/global config, credential helpers, prompts, file/SSH/ext protocols, hooks,
recursive submodules, replace objects, filesystem monitors, external attributes,
auto-GC and maintenance are disabled. All arguments are arrays. A fresh bare
repository is initialized with no templates; no worktree checkout is performed,
so smudge filters and checkout hooks cannot run. Fetch/fsck use the full immutable
commit, not a branch. Git child processes have CPU (60 seconds), address-space
(512 MiB), descriptor (128), core-dump (zero) and file-size (128 MiB) limits. Pack
transfer/output and export sizes are bounded. Operators must also apply aggregate
filesystem quotas; the per-file limit is not a global host disk quota.

## Discovery and local inputs

At most 64 JSON/YAML candidate files are inspected at the repository root and one
level below flatpak/, packaging/, build-aux/. Candidates must pass the SAME M1
validator, with its project-local-source context. More than one valid manifest
returns `multiple_manifests_found` and a stable sorted candidate list. An explicit
manifest_path selects exactly one file. Invalid/missing manifests are recorded as
source event failures and are visible in project history.

Only committed, regular files are exported. Git submodules/gitlinks, symlinks,
hard links and special files are rejected. Git archive's bounded global metadata
is ignored; paths are still checked before use. The normalized snapshot is a
sorted tar with zero timestamps/UID/GID and 0644/0755 modes. It is capped at 64 MiB
including tar structure and 4,096 files, and SHA-256 hashed. Git export-ignore/
export-subst attributes can affect exported content; the separate digest records
that content rather than assuming Git SHA alone defines the snapshot. LFS smudge
and generated host files are not supported.

Local file, archive, patch and directory sources are supported through safe `path`
values. Paths resolve relative to the selected manifest's directory and must remain
within exported files, without parent traversal. Modules/includes from external
manifest files remain unsupported. Local directory sources must contain at least
one exported file. Normalized paths are `source/<repository-relative path>`.
All other existing M1 validation and source-download policies still apply.

A snapshot is saved with fsync/atomic no-overwrite placement before M1 handoff.
The Docker executor rehashes/reparses it and validates local file membership before
rebuilding a private safe tree. It copies that tree into `/work/source` and the
normalized manifest to `/work/manifest.json`; no checkout or host directory is
mounted. Only the bundle returns from the untrusted container. Recovery refetches
the recorded SHA and requires the prepared digest to match any retained snapshot.
Queued M1 builds recheck the persisted snapshot before use. Failed interrupted M1
builds retain immutable history, following existing M1 semantics.

## CI-only fixture

The real transport tests create a fresh Git repository and CA/leaf TLS certificate
with scripts/source_fixture.py. An operator-only exact fixture mapping is enabled
by LIBREHUB_TEST_SOURCE_REPOSITORY=https://git.librehub.test/fixture.git,
LIBREHUB_TEST_SOURCE_CA_FILE and LIBREHUB_TEST_SOURCE_PORT. Only that identity maps
to loopback TLS; no API request can choose a private destination or CA. Leave these
variables unset in deployment. Debug acceptance binaries have fixture-only crash
barriers; release builds compile them out. The tests still perform actual HTTPS,
Git revision resolution/fetch/archive, M1 execution and M2 signed installation.
