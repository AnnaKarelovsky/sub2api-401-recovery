# Codex Model Sync

`codex-model-sync` keeps the Codex CLI custom model catalog aligned with the
OpenAI-compatible API configured in `~/.codex/config.toml`.

The command reads `openai_base_url`, calls `/models` with the API key from
`~/.codex/auth.json`, and updates the configured `model_catalog_json` file.
Unknown upstream models receive the metadata template already used by the
catalog. Models that disappear from the upstream response are hidden and kept
in place so a temporary upstream problem does not destroy local metadata.

Run a manual sync:

```sh
codex-model-sync --show-models
```

The installed user systemd timer fetches models every day at 00:00 in the host
timezone. When the catalog changes, it attempts an app-server restart only if
the app-server has been quiet for 10 minutes. A second user timer retries a
deferred restart every five minutes, so an active task is not interrupted.
The activity check reads the current app-server process's local Codex log; if
that log cannot be read, the restart is deferred conservatively.

Check both timers with:

```sh
systemctl --user status codex-model-sync.timer
systemctl --user status codex-model-sync-idle.timer
journalctl --user -u codex-model-sync.service
```

Each changed catalog is backed up beside the catalog as
`models-custom.json.backup-<UTC timestamp>`. Start a new Codex CLI session
after a successful restart so the UI reloads the catalog from disk. To apply a
pending restart manually after checking that no task is active, run:

```sh
codex-model-sync --apply-pending
```

`--force-restart --apply-pending` is available for an operator who accepts
interrupting active work.
