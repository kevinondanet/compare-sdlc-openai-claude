# Harness adapter templates

One directory per harness (`claude_code/`, `copilot/`, `codex/`, `cursor/`, `kiro/`).
`aisdlc adapter emit <harness>` renders these with `string.Template.safe_substitute`, so
`$name` placeholders are filled from `AdapterContext.substitutions()` and unknown ones
(host syntax such as `$ARGUMENTS`, `${input:...}`) are left untouched; write `$$` for a
literal dollar sign.

Shared placeholders: `$project_name`, `$org_policy_name`, `$role`, `$hook_command`,
`$workflow`, `$commands`, `$command_briefs`, `$artifacts`, `$tool_policy`,
`$policy_summary`, `$test_commands`, `$gates`. Per-file placeholders (`$title`, `$brief`,
`$cli`, `$allowed_tools`, `$tools`, `$steps`, ...) are documented in the adapter module.

Each file must stay byte-identical to the `DEFAULT_TEMPLATES` entry embedded in
`src/aisdlc/adapters/<harness>.py` (the embedded copy is used when the repository
templates are not on disk); `tests/test_adapters_harness.py` asserts this.
