"""``aisdlc gate`` — evaluate gates, write the verdict, sign and verify the evidence bundle."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from aisdlc.cli import _common as common
from aisdlc.gates import depth as depthmod
from aisdlc.gates import gates as gatesmod
from aisdlc.gates import verdict as verdictmod
from aisdlc.policy import merge as policy_merge
from aisdlc.policy import org_policy as orgmod
from aisdlc.policy import project_config as projmod
from aisdlc.schema import fingerprint as fingerprintmod
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import ChangePackage, FinalVerdict, GateId, GateResult, RiskClass

NAME = "gate"
app = typer.Typer(
    help="Progressive gates G0..G6, final verdict and signed evidence bundle.",
    no_args_is_help=True,
)

_ORG_OPT = typer.Option(None, "--org", help="org-policy.yaml (auto-discovered if omitted).")
_PROJECT_OPT = typer.Option(
    None, "--project", help="project-config.yaml (auto-discovered if omitted)."
)
_ROOT_OPT = typer.Option(Path("."), "--root", help="Directory searched for policy files.")
_RISK_OPT = typer.Option(
    None, "--risk", help="Override the intent's risk class for depth selection."
)
_JSON_OPT = typer.Option(False, "--json", help="Machine-readable output.")


def _load(directory: Path) -> ChangePackage:
    try:
        return pkgio.load(directory)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _policy(org: Path | None, project: Path | None, root: Path) -> policy_merge.EffectivePolicy:
    org_path = org if org is not None else orgmod.find_org_policy(root)
    project_path = project if project is not None else projmod.find_project_config(root)
    try:
        org_policy = orgmod.load_org_policy(org_path) if org_path else orgmod.default_org_policy()
        project_config = (
            projmod.load_project_config(project_path)
            if project_path
            else projmod.default_project_config()
        )
    except orgmod.PolicyLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    return policy_merge.effective_policy(org_policy, project_config)


def _profile(
    package: ChangePackage, policy: orgmod.OrgPolicy, risk: RiskClass | None
) -> depthmod.GateDepthProfile:
    return depthmod.profile_for(risk or package.intent.risk_class, policy)


def _root(directory: Path, root: Path) -> Path:
    """Policy/key discovery root: ``--root`` when given, else the repo holding the package."""
    return root if root != Path(".") else common.repo_root_for(directory)


def _hmac_key(explicit: Path | None, root: Path) -> bytes | None:
    """HMAC key from ``--hmac-key-file``, else ``<root>/.aisdlc/signing.key`` (env wins)."""
    if explicit is not None:
        try:
            text = explicit.read_text(encoding="utf-8").strip()
        except OSError as exc:
            typer.echo(f"error: cannot read {explicit}: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        try:
            return bytes.fromhex(text)
        except ValueError:
            return text.encode("utf-8")
    if verdictmod.hmac_key_from_env():
        return None
    return common.read_hmac_key_file(root)


_HMAC_OPT = typer.Option(
    None,
    "--hmac-key-file",
    help="File holding the HMAC key (hex or raw); default $AISDLC_SIGNING_KEY, "
    "then <root>/.aisdlc/signing.key (written by `aisdlc init`).",
)


def _context(
    package: ChangePackage, directory: Path, hmac_key_file: Path | None, root: Path
) -> gatesmod.GateContext:
    """Gate context with the same signing-key discovery ``gate bundle`` uses."""
    return gatesmod.GateContext.from_package(package, hmac_key=_hmac_key(hmac_key_file, root))


def _stale_reason(directory: Path, existing: FinalVerdict | None, commit: str | None) -> str | None:
    """Why an existing ``final-verdict.json`` no longer applies to the package on disk."""
    if existing is None:
        return None
    current_fp = fingerprintmod.compute_fingerprint(directory)
    if not existing.fingerprint:
        return "existing final-verdict.json records no package fingerprint"
    if existing.fingerprint != current_fp:
        return (
            "package content changed since final-verdict.json was evaluated "
            f"({existing.fingerprint[:12]}… -> {current_fp[:12]}…)"
        )
    head = commit or verdictmod.git_head(directory)
    if head and existing.commit_sha and existing.commit_sha != head:
        return (
            f"final-verdict.json was evaluated at {existing.commit_sha[:12]} but the bundle "
            f"would certify {head[:12]}"
        )
    return None


def _print_result(result: GateResult) -> None:
    gate = gatesmod.gate_for(result.gate)
    if result.depth.value == "skipped":
        status = "SKIP"
    else:
        status = "PASS" if result.passed else "FAIL"
    typer.echo(f"{result.gate.value} {status:<4} [{result.depth.value}] {gate.title}")
    for reason in result.reasons:
        typer.echo(f"    - {reason}")


@app.command("evaluate")
def evaluate(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    gate: GateId | None = typer.Option(None, "--gate", "-g", help="Evaluate one gate only."),
    risk: RiskClass | None = _RISK_OPT,
    org: Path | None = _ORG_OPT,
    project: Path | None = _PROJECT_OPT,
    root: Path = _ROOT_OPT,
    hmac_key_file: Path | None = _HMAC_OPT,
    as_json: bool = _JSON_OPT,
) -> None:
    """Evaluate gates without writing anything; exit 1 when a required gate fails."""
    package = _load(directory)
    base_root = _root(directory, root)
    policy = _policy(org, project, base_root)
    profile = _profile(package, policy, risk)
    context = _context(package, directory, hmac_key_file, base_root)
    runner = gatesmod.GateRunner()
    if gate is not None:
        results = [runner.evaluate(gate, package, policy, profile, context)]
    else:
        results = list(runner.evaluate_all(package, policy, profile, context).gate_results)
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "change_id": package.change_id,
                    "risk_class": profile.risk_class.value,
                    "depth": profile.depth.value,
                    "results": [r.model_dump(mode="json") for r in results],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        typer.echo(
            f"{package.change_id}: risk {profile.risk_class.value}, depth {profile.depth.value}"
        )
        for result in results:
            _print_result(result)
    if any(not r.passed for r in results):
        raise typer.Exit(code=1)


@app.command("verdict")
def verdict(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    risk: RiskClass | None = _RISK_OPT,
    org: Path | None = _ORG_OPT,
    project: Path | None = _PROJECT_OPT,
    root: Path = _ROOT_OPT,
    hmac_key_file: Path | None = _HMAC_OPT,
    write: bool = typer.Option(True, "--write/--no-write", help="Write final-verdict.json."),
    as_json: bool = _JSON_OPT,
) -> None:
    """Evaluate every gate and write the (unsigned) final verdict; exit 1 when negative."""
    package = _load(directory)
    base_root = _root(directory, root)
    policy = _policy(org, project, base_root)
    profile = _profile(package, policy, risk)
    context = _context(package, directory, hmac_key_file, base_root)
    result = gatesmod.GateRunner().evaluate_all(package, policy, profile, context)
    if write:
        verdictmod.write_verdict(directory, result)
    if as_json:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        for gate_result in result.gate_results:
            _print_result(gate_result)
        typer.echo(f"overall: {'PASS' if result.overall else 'FAIL'}")
        if write:
            typer.echo(f"wrote {directory / pkgio.FINAL_VERDICT_FILE}")
    if not result.overall:
        raise typer.Exit(code=1)


@app.command("approve")
def approve(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    role: str = typer.Option(..., "--role", "-r", help="Approver role (owner, security, ...)."),
    approver: str = typer.Option(..., "--approver", "-a", help="Human identity."),
    note: str = typer.Option("", "--note", help="Optional note."),
) -> None:
    """Record a human approval in approvals.json (consumed by G6 and the bundle)."""
    if not (directory / pkgio.INTENT_FILE).is_file():
        typer.echo(f"error: not a change package: {directory}", err=True)
        raise typer.Exit(code=2)
    approvals = verdictmod.add_approval(
        directory, verdictmod.Approval(role=role, approver=approver, note=note)
    )
    typer.echo(f"recorded approval by {approver} as {role} ({len(approvals)} total)")


@app.command("bundle")
def bundle(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    signer: str = typer.Option("aisdlc", "--signer", help="Signer identity recorded."),
    ed25519_key: Path | None = typer.Option(
        None, "--ed25519-key", help="PEM Ed25519 private key (or $AISDLC_ED25519_PRIVATE_KEY)."
    ),
    commit: str | None = typer.Option(None, "--commit", help="Commit sha (default: HEAD)."),
    hmac_key_file: Path | None = _HMAC_OPT,
    risk: RiskClass | None = _RISK_OPT,
    org: Path | None = _ORG_OPT,
    project: Path | None = _PROJECT_OPT,
    root: Path = _ROOT_OPT,
    as_json: bool = _JSON_OPT,
) -> None:
    """Build and sign the evidence bundle.

    Evaluates the gates first when no verdict exists, or when the existing verdict was
    evaluated against different package content or a different commit — a stale verdict
    is never re-signed.
    """
    if not (directory / pkgio.INTENT_FILE).is_file():
        typer.echo(f"error: not a change package: {directory}", err=True)
        raise typer.Exit(code=2)
    try:
        existing = verdictmod.read_verdict(directory)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    base_root = _root(directory, root)
    stale = _stale_reason(directory, existing, commit)
    if existing is None or stale is not None:
        package = _load(directory)
        policy = _policy(org, project, base_root)
        profile = _profile(package, policy, risk)
        context = _context(package, directory, hmac_key_file, base_root)
        existing = gatesmod.GateRunner().evaluate_all(package, policy, profile, context)
        verdictmod.write_verdict(directory, existing)
        why = "no final-verdict.json" if stale is None else stale
        typer.echo(
            f"{why}; evaluated gates first (overall {'PASS' if existing.overall else 'FAIL'})"
        )
    try:
        manifest, final = verdictmod.publish_bundle(
            directory,
            existing,
            signer=signer,
            hmac_key=_hmac_key(hmac_key_file, base_root),
            ed25519_private_key=ed25519_key,
            commit_sha=commit,
        )
    except verdictmod.BundleError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if as_json:
        typer.echo(json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    typer.echo(f"bundle digest {manifest.digest()}")
    for signature in manifest.signatures:
        typer.echo(f"signed {signature.algorithm} by {signature.signer}")
    typer.echo(f"files: {len(manifest.files)}, approvals: {len(manifest.approvals)}")
    typer.echo(
        f"wrote {directory / verdictmod.BUNDLE_FILE} and {directory / pkgio.FINAL_VERDICT_FILE}"
    )
    if not final.overall:
        typer.echo("note: the certified verdict is negative (overall=false)", err=True)


@app.command("verify-bundle")
def verify_bundle_cmd(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    public_key: list[Path] | None = typer.Option(
        None, "--public-key", help="PEM Ed25519 public key(s) (or $AISDLC_ED25519_PUBLIC_KEY)."
    ),
    head: str | None = typer.Option(None, "--head", help="Expected commit (default: git HEAD)."),
    require_head: bool = typer.Option(
        False, "--require-head", help="Fail when git HEAD cannot be determined."
    ),
    hmac_key_file: Path | None = _HMAC_OPT,
    risk: RiskClass | None = _RISK_OPT,
    org: Path | None = _ORG_OPT,
    project: Path | None = _PROJECT_OPT,
    root: Path = _ROOT_OPT,
    as_json: bool = _JSON_OPT,
) -> None:
    """Verify the signed bundle (what release automation calls); exit 1 on any failure."""
    package = _load(directory)
    policy = _policy(org, project, _root(directory, root))
    profile = _profile(package, policy, risk)
    result = verdictmod.verify_bundle(
        directory,
        hmac_key=_hmac_key(hmac_key_file, _root(directory, root)),
        ed25519_public_keys=public_key or None,
        head_commit=head,
        require_head=require_head,
        max_age_hours=profile.evidence_max_age_hours,
        min_signatures=profile.min_signatures if profile.require_signatures else 0,
        allowed_algorithms=profile.signature_algorithms,
        min_approvals=profile.min_approvals if profile.human_approval_required else 0,
        required_roles=profile.required_approval_roles,
    )
    if as_json:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        typer.echo(f"bundle {'OK' if result.ok else 'FAILED'} digest={result.digest}")
        typer.echo(
            f"signatures valid={result.valid_signatures} invalid={result.invalid_signatures} "
            f"approvals={result.approvals} tampered={result.tampered} stale={result.stale}"
        )
        for reason in result.reasons:
            typer.echo(f"    - {reason}")
    if not result.ok:
        raise typer.Exit(code=1)
