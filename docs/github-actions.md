# GitHub Actions integration and the `librehub` CLI (M7)

## Onboarding

1. **Create a project** (any developer token):
   `librehub project create --slug hello --name Hello --repository https://github.com/octo/hello --default-branch main`
   (the one-time webhook secret is printed; configure it in GitHub if you also want M3 push webhooks).
2. **Define a release automation** — `librehub automation create --project $P --file release.yml`
   with a `ci` trigger (see [automation.md](automation.md)). Validate offline first:
   `librehub automation validate --file release.yml`.
3. **Trust the repository's identity** (deny by default; see [oidc-federation.md](oidc-federation.md)):
   `librehub integration oidc-add --project $P --name release --policy policy.json`.
   The server must have `LIBREHUB_OIDC_AUDIENCE` set.
4. **Add the action to the workflow** (below). No LibreHub secret is needed in GitHub.
5. Push. Watch with `librehub automation status --project $P $RUN` or the dashboard
   (`/dashboard/projects/<id>/runs`); read build logs with `librehub build logs $BUILD --follow`.
6. When the pipeline reaches the approval step, an owner (or listed approver) runs
   `librehub approval list` and `librehub approval approve <id> --reason …`. The CI job cannot.
7. Install the stable release with the normal Flatpak client:
   `flatpak remote-add --user librehub https://<repo>/librehub.flatpakrepo && flatpak install librehub <app-id>`.
8. Subscribe to events: [outbound-webhooks.md](outbound-webhooks.md).

## The action

`actions/librehub` is a composite action in this repository. It builds the CLI from the same
pinned checkout (`cargo install --locked --path services/cli`; set `cli-path` to use a
pre-built binary) and runs `librehub ci <operation>`.

```yaml
name: LibreHub release
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read    # checkout
  id-token: write   # request the OIDC identity token — nothing more is granted
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full commit SHA>
        with: { persist-credentials: false }
      - id: beta
        uses: c8dhjp4tyv-bit/LibreHub/actions/librehub@<full commit SHA of a reviewed revision>
        with:
          librehub-url: https://librehub.example
          project-id: 00000000-0000-0000-0000-000000000000
          operation: build-and-publish-beta
```

The example in `examples/github-actions/librehub-release.yml` is documentation with
`COMMIT_SHA`/URL placeholders and has **not** been executed. The usage that CI does execute is
the `github-oidc-integration` job in `.github/workflows/ci.yml`, which runs `./actions/librehub`
with a real GitHub-issued token against a locally started LibreHub.

Inputs: `librehub-url`, `project-id`, `operation`, `automation` (name or ID, default
`Release Pipeline`), `audience` (default `librehub`, must equal the server's
`LIBREHUB_OIDC_AUDIENCE`), `timeout-seconds` (default 1800), `cli-path`.

Operations (every one first triggers idempotently — the key is the GitHub run attempt — so any
operation can be used in any job and receives the same automation run):

| `operation` | Waits for | Main outputs |
| --- | --- | --- |
| `build` | nothing | `run_id`, `source_commit`, `source_event_id`, `build_id` |
| `wait-for-build` | build step | `build_status` |
| `verify-provenance` | verify step | `attestation_status` |
| `publish-beta` / `build-and-publish-beta` | beta publication | `publication_id`, `publication_status`, `flatpak_ref` |
| `wait-for-security` | M5 analysis step | — |
| `request-promotion` | approval requested | `approval_id` |
| `wait-for-publication` | stable publication + its attestation | stable `publication_id`, `publication_status`, `flatpak_ref`, `attestation_status` |

All outputs: `run_id run_status source_commit source_event_id build_id build_status
publication_id publication_status flatpak_ref attestation_status approval_id`. The CLI writes
single-line values to `$GITHUB_OUTPUT` (multi-line values are dropped to prevent output
injection), masks credentials with `::add-mask::`, and prints no token.

Security notes: inputs reach the shell only through `env:`; pin the action to a full commit SHA;
pull-request workflows cannot obtain a runnable credential; the exchanged credential lives only
in the CLI process (the CLI also refuses `auth login` inside Actions). Updating GitHub
check runs/statuses is **not** implemented: an OIDC identity token is not a GitHub API token,
and GitHub App installation credentials are out of scope (M8+).

### Duplicate builds

A webhook delivery, an OIDC-triggered run, a schedule and a manual run that concern the same
commit converge: the build step reuses an existing in-flight or successful build of that commit
(any origin) unless `fresh_build` is requested. M3's own `POST /projects/{id}/builds` remains an
explicit, independent build.

## CLI

`librehub [--api-url URL] [--json] [--timeout SECONDS] <command>` — `LIBREHUB_URL`,
`LIBREHUB_TIMEOUT`, `LIBREHUB_TOKEN`, `LIBREHUB_OIDC_PROJECT`, `LIBREHUB_OIDC_AUDIENCE`.

| Command | Backed by |
| --- | --- |
| `auth login --token-stdin` / `logout` / `status` | `GET /api/v1/whoami` |
| `project list|show|create` | `/api/v1/projects` |
| `build trigger|status|logs` (`--wait`, `--follow`) | `/projects/{id}/builds`, `/builds/{id}[/logs]` |
| `publish beta|stable` (`--wait`; stable needs `--yes`) | `/builds/{id}/publish` |
| `automation list|show|create|update|validate|run|status|logs|cancel|runs` | automation API |
| `approval list|show|approve|reject` | approval API |
| `integration list|oidc-add|oidc-revoke|webhook-add|webhook-rotate|webhook-delete|deliveries|replay` | integration API |
| `verify --app A --release P [--trusted-keys FILE]` | public provenance + DSSE verification |
| `ci <operation>` | automation run API |

Credentials, in order: `--oidc-project` (GitHub Actions identity, exchanged in memory), then
`LIBREHUB_TOKEN`, then the stored file `~/.config/librehub/credentials.json` (mode 0600, keyed by
server origin, refused if group/world accessible). Tokens are never accepted as arguments or
placed in URLs; non-loopback `http://` API URLs are refused; redirects are not followed; TLS is
always verified.

Output: human tables by default, one JSON document on stdout with `--json`
(errors as `{"error":{"code","message","status","exit_code"}}` on stderr). Waiting is bounded by
`--timeout` with 0.5 s → 5 s backoff; Ctrl-C stops waiting (the run continues server side).

Exit codes: `0` ok, `1` other, `2` usage/configuration, `3` authentication or authorization,
`4` not found, `5` timeout, `6` the awaited operation failed or was cancelled, `7` conflict,
`8` server/network unavailable, `130` interrupted.
