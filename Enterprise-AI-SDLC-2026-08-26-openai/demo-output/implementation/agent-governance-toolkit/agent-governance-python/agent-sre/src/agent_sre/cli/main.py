# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
agent-sre CLI — command-line interface for Agent SRE.

Usage:
    python -m agent_sre.cli slo status
    python -m agent_sre.cli slo list
    python -m agent_sre.cli cost summary
    python -m agent_sre.cli version
"""

import argparse
import json
import os
import sys
import tempfile
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any


def _atomic_write(path: str | Path, payload: bytes) -> None:
    destination = Path(path)
    if not destination.parent.exists():
        raise ValueError(f"output parent directory does not exist: {destination.parent}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def cli(args: list[str] | None = None) -> int:
    """Main CLI entry point. Returns exit code."""
    parser = argparse.ArgumentParser(
        prog="agent-sre",
        description="Reliability Engineering for AI Agent Systems",
    )
    subparsers = parser.add_subparsers(dest="command")

    # slo subcommand
    slo_parser = subparsers.add_parser("slo", help="SLO management")
    slo_sub = slo_parser.add_subparsers(dest="slo_command")
    slo_sub.add_parser("status", help="Show SLO health status")
    slo_sub.add_parser("list", help="List all SLOs")

    # cost subcommand
    cost_parser = subparsers.add_parser("cost", help="Cost management")
    cost_sub = cost_parser.add_subparsers(dest="cost_command")
    cost_sub.add_parser("summary", help="Show cost summary")

    # version subcommand
    subparsers.add_parser("version", help="Show version")

    # info subcommand
    subparsers.add_parser("info", help="Show system info")

    # release subcommand
    release_parser = subparsers.add_parser("release", help="Evidence-backed release decisions")
    release_sub = release_parser.add_subparsers(dest="release_command")
    evaluate_parser = release_sub.add_parser(
        "evaluate", help="Evaluate PyRIT security evidence against release policy"
    )
    evaluate_parser.add_argument("--policy", required=True, help="agt.release-policy/v1 JSON")
    evaluate_parser.add_argument("--evidence", required=True, help="PyRIT security evidence JSON")
    evaluate_parser.add_argument("--ledger", help="SQLite evaluation ledger path")
    evaluate_parser.add_argument("--output", help="Write canonical verdict JSON to this path")
    evaluate_parser.add_argument(
        "--evaluated-at", help="UTC ISO-8601 evaluation time (primarily for reproducible CI)"
    )
    evaluate_parser.add_argument("--signing-key", help="Ed25519 private key PEM")
    evaluate_parser.add_argument("--signer-did", help="Optional DID recorded in the signature")
    evaluate_parser.add_argument("--signature-output", help="Signature JSON output path")

    verify_parser = release_sub.add_parser(
        "verify", help="Verify a signed canonical release verdict"
    )
    verify_parser.add_argument("--bundle", required=True, help="agt.release-verdict/v1 JSON")
    verify_parser.add_argument("--signature", required=True, help="Signature bundle JSON")
    verify_parser.add_argument(
        "--policy", required=True, help="Protected agt.release-policy/v1 JSON"
    )
    verify_parser.add_argument(
        "--evidence", required=True, help="Protected PyRIT security evidence JSON"
    )
    verify_parser.add_argument(
        "--trusted-public-key",
        required=True,
        help="Trusted Ed25519 public key as hex or an absolute hex-file path",
    )

    # enterprise SDLC subcommand
    sdlc_parser = subparsers.add_parser("sdlc", help="Progressive enterprise G0-G6 gates")
    sdlc_sub = sdlc_parser.add_subparsers(dest="sdlc_command")
    sdlc_evaluate = sdlc_sub.add_parser(
        "evaluate", help="Evaluate a canonical change and its machine evidence"
    )
    sdlc_evaluate.add_argument("--change", required=True, help="agt.change/v1 JSON")
    sdlc_evaluate.add_argument(
        "--orchestration-manifest",
        required=True,
        help="Governed agt.orchestration-manifest/v1 JSON",
    )
    sdlc_evaluate.add_argument(
        "--execution-receipt",
        required=True,
        help="Final agt.orchestration-execution-receipt/v1 JSON",
    )
    sdlc_evaluate.add_argument(
        "--evidence",
        action="append",
        default=[],
        help="agt.execution-evidence/v1 JSON (repeat for each artifact)",
    )
    sdlc_evaluate.add_argument(
        "--approval",
        action="append",
        default=[],
        help="agt.human-approval/v1 JSON (repeat for each approval)",
    )
    sdlc_evaluate.add_argument(
        "--organization-enterprise-policy",
        required=True,
        help="Protected organization agt.enterprise-gate-policy/v1 JSON",
    )
    sdlc_evaluate.add_argument(
        "--organization-development-policy",
        required=True,
        help="Protected organization agt.development-policy/v1 JSON",
    )
    sdlc_evaluate.add_argument(
        "--organization-orchestration-policy",
        required=True,
        help="Protected organization agt.orchestration-policy/v1 JSON",
    )
    sdlc_evaluate.add_argument(
        "--organization-release-policy",
        help="Protected organization agt.release-policy/v1 JSON for PyRIT gates",
    )
    sdlc_evaluate.add_argument(
        "--project-enterprise-policy",
        help="Optional project overlay; it may only narrow organization policy",
    )
    sdlc_evaluate.add_argument(
        "--project-development-policy",
        help="Optional project overlay; it may only narrow organization policy",
    )
    sdlc_evaluate.add_argument(
        "--project-orchestration-policy",
        help="Optional orchestration overlay; it may only narrow organization policy",
    )
    sdlc_evaluate.add_argument(
        "--project-release-policy",
        help="Optional project PyRIT overlay; it may only narrow organization policy",
    )
    sdlc_evaluate.add_argument("--pyrit-evidence", help="pyrit.security-evidence/v1 JSON")
    sdlc_evaluate.add_argument(
        "--risk-classification",
        required=True,
        help="Organization-signed agt.risk-classification/v1 JSON",
    )
    sdlc_evaluate.add_argument(
        "--evaluated-at", help="UTC ISO-8601 evaluation time (primarily for reproducible CI)"
    )
    sdlc_evaluate.add_argument(
        "--output", required=True, help="Write canonical agt.enterprise-readiness/v1 JSON"
    )

    sdlc_issue = sdlc_sub.add_parser(
        "issue", help="Re-evaluate trusted inputs and sign the exact readiness bundle"
    )
    sdlc_issue.add_argument("--readiness", required=True, help="Unsigned readiness bundle JSON")
    sdlc_issue.add_argument("--change", required=True, help="Protected agt.change/v1 JSON")
    sdlc_issue.add_argument(
        "--orchestration-manifest",
        required=True,
        help="Protected agt.orchestration-manifest/v1 JSON",
    )
    sdlc_issue.add_argument(
        "--execution-receipt",
        required=True,
        help="Protected final orchestration receipt JSON",
    )
    sdlc_issue.add_argument(
        "--evidence",
        action="append",
        default=[],
        help="Protected agt.execution-evidence/v1 JSON (repeat for each artifact)",
    )
    sdlc_issue.add_argument(
        "--approval",
        action="append",
        default=[],
        help="Protected agt.human-approval/v1 JSON (repeat for each approval)",
    )
    sdlc_issue.add_argument(
        "--organization-enterprise-policy",
        required=True,
        help="Protected organization agt.enterprise-gate-policy/v1 JSON",
    )
    sdlc_issue.add_argument(
        "--organization-development-policy",
        required=True,
        help="Protected organization agt.development-policy/v1 JSON",
    )
    sdlc_issue.add_argument(
        "--organization-orchestration-policy",
        required=True,
        help="Protected organization agt.orchestration-policy/v1 JSON",
    )
    sdlc_issue.add_argument(
        "--organization-release-policy",
        help="Protected organization agt.release-policy/v1 JSON for PyRIT gates",
    )
    sdlc_issue.add_argument(
        "--project-enterprise-policy",
        help="Optional project overlay; it may only narrow organization policy",
    )
    sdlc_issue.add_argument(
        "--project-development-policy",
        help="Optional project overlay; it may only narrow organization policy",
    )
    sdlc_issue.add_argument(
        "--project-orchestration-policy",
        help="Optional orchestration overlay; it may only narrow organization policy",
    )
    sdlc_issue.add_argument(
        "--project-release-policy",
        help="Optional project PyRIT overlay; it may only narrow organization policy",
    )
    sdlc_issue.add_argument("--pyrit-evidence", help="Protected pyrit.security-evidence/v1 JSON")
    sdlc_issue.add_argument(
        "--risk-classification",
        required=True,
        help="Protected organization-signed agt.risk-classification/v1 JSON",
    )
    sdlc_issue.add_argument(
        "--trusted-change-digest",
        required=True,
        help="Protected canonical change SHA-256 trust anchor",
    )
    sdlc_issue.add_argument(
        "--trusted-effective-policy-digest",
        required=True,
        help="Protected effective project-policy SHA-256 trust anchor",
    )
    sdlc_issue.add_argument("--output", required=True, help="Issued readiness bundle path")
    sdlc_issue.add_argument("--signing-key", required=True, help="Ed25519 private key PEM")
    sdlc_issue.add_argument("--signature-output", help="Release signature sidecar path")
    sdlc_issue.add_argument("--signer-did", help="Optional DID recorded in the signature sidecar")

    sdlc_verify = sdlc_sub.add_parser(
        "verify", help="Verify enterprise release issuance against a pinned public key"
    )
    sdlc_verify.add_argument("--bundle", required=True, help="Issued readiness bundle JSON")
    sdlc_verify.add_argument("--signature", required=True, help="Release signature sidecar JSON")
    sdlc_verify.add_argument(
        "--expected-change",
        required=True,
        help="Protected canonical change expected by this deployment",
    )
    sdlc_verify.add_argument(
        "--expected-orchestration-manifest",
        required=True,
        help="Protected orchestration manifest expected by this deployment",
    )
    sdlc_verify.add_argument(
        "--expected-execution-receipt",
        required=True,
        help="Protected final execution receipt expected by this deployment",
    )
    sdlc_verify.add_argument(
        "--organization-enterprise-policy",
        required=True,
        help="Protected organization agt.enterprise-gate-policy/v1 JSON",
    )
    sdlc_verify.add_argument(
        "--organization-development-policy",
        required=True,
        help="Protected organization agt.development-policy/v1 JSON",
    )
    sdlc_verify.add_argument(
        "--organization-orchestration-policy",
        required=True,
        help="Protected organization agt.orchestration-policy/v1 JSON",
    )
    sdlc_verify.add_argument(
        "--organization-release-policy",
        help="Protected organization agt.release-policy/v1 JSON for PyRIT gates",
    )
    sdlc_verify.add_argument("--project-enterprise-policy")
    sdlc_verify.add_argument("--project-development-policy")
    sdlc_verify.add_argument("--project-orchestration-policy")
    sdlc_verify.add_argument("--project-release-policy")
    sdlc_verify.add_argument(
        "--trusted-change-digest",
        required=True,
        help="Protected canonical change SHA-256 trust anchor",
    )
    sdlc_verify.add_argument(
        "--trusted-effective-policy-digest",
        required=True,
        help="Protected effective project-policy SHA-256 trust anchor",
    )
    sdlc_verify.add_argument(
        "--trusted-public-key",
        required=True,
        help="Trusted Ed25519 public key as hex or a hex file",
    )

    parsed = parser.parse_args(args)

    if parsed.command == "version":
        print("agent-sre 0.1.0")
        return 0

    if parsed.command == "info":
        info: dict[str, Any] = {
            "name": "agent-sre",
            "version": "0.1.0",
            "engines": ["slo", "cost", "chaos", "delivery", "replay", "incidents"],
            "integrations": [
                "agent_os",
                "agent_mesh",
                "otel",
                "langchain",
                "llamaindex",
                "langfuse",
                "arize",
                "braintrust",
                "helicone",
                "datadog",
                "langsmith",
                "mcp",
                "prometheus",
            ],
            "adapters": [
                "langgraph",
                "crewai",
                "autogen",
                "openai_agents",
                "semantic_kernel",
                "dify",
            ],
        }
        print(json.dumps(info, indent=2))
        return 0

    if parsed.command == "slo":
        if parsed.slo_command == "status":
            print("No SLOs configured. Use the Python API to register SLOs.")
            return 0
        if parsed.slo_command == "list":
            print("No SLOs registered.")
            return 0
        slo_parser.print_help()
        return 1

    if parsed.command == "cost":
        if parsed.cost_command == "summary":
            print("No cost data available. Use the Python API to record costs.")
            return 0
        cost_parser.print_help()
        return 1

    if parsed.command == "release":
        if parsed.release_command == "evaluate":
            from agent_sre.sdlc import (
                ReleaseEvaluator,
                SQLiteEvaluationLedger,
                VerdictStatus,
                canonical_json_bytes,
                load_pyrit_security_evidence,
                load_release_policy,
                sign_release_bundle,
                write_signature_bundle,
            )

            ledger = None
            try:
                if parsed.signing_key and not parsed.output:
                    raise ValueError("--signing-key requires --output")
                if parsed.signature_output and not parsed.signing_key:
                    raise ValueError("--signature-output requires --signing-key")
                if parsed.signing_key and parsed.evaluated_at:
                    raise ValueError("--evaluated-at cannot be used when signing")
                policy = load_release_policy(parsed.policy)
                evidence = load_pyrit_security_evidence(parsed.evidence)
                if parsed.ledger:
                    ledger = SQLiteEvaluationLedger(parsed.ledger)
                evaluated_at = (
                    datetime.fromisoformat(parsed.evaluated_at.replace("Z", "+00:00"))
                    if parsed.evaluated_at
                    else None
                )
                verdict = ReleaseEvaluator(ledger).evaluate(
                    policy, evidence, evaluated_at=evaluated_at
                )
                encoded = canonical_json_bytes(verdict) + b"\n"
                if parsed.output:
                    _atomic_write(parsed.output, encoded)
                sys.stdout.buffer.write(encoded)
                if parsed.signing_key:
                    signature = sign_release_bundle(
                        parsed.output,
                        policy=policy,
                        evidence=evidence,
                        private_key_path=parsed.signing_key,
                        signer_did=parsed.signer_did,
                    )
                    signature_output = parsed.signature_output or f"{parsed.output}.sig.json"
                    write_signature_bundle(signature_output, signature)
                return 0 if verdict.status is VerdictStatus.PASS else 1
            except Exception as exc:
                print(f"release evaluation error: {exc}", file=sys.stderr)
                return 2
            finally:
                if ledger is not None:
                    ledger.close()

        if parsed.release_command == "verify":
            from agent_sre.sdlc import (
                load_pyrit_security_evidence,
                load_release_policy,
            )
            from agent_sre.sdlc.signing import (
                load_signature_bundle,
                load_trusted_public_key,
                verify_release_bundle,
            )

            try:
                signature = load_signature_bundle(parsed.signature)
                trusted_key = load_trusted_public_key(parsed.trusted_public_key)
                policy = load_release_policy(parsed.policy)
                evidence = load_pyrit_security_evidence(parsed.evidence)
                valid = verify_release_bundle(
                    parsed.bundle,
                    signature,
                    trusted_public_key=trusted_key,
                    expected_policy=policy,
                    expected_evidence=evidence,
                )
                print(json.dumps({"verified": valid}, sort_keys=True))
                return 0 if valid else 1
            except Exception as exc:
                print(f"release verification error: {exc}", file=sys.stderr)
                return 2

        release_parser.print_help()
        return 1

    if parsed.command == "sdlc":
        from agent_sre.sdlc.canonical import canonical_json_bytes, load_json_file_strict
        from agent_sre.sdlc.change_contract import ChangePackage
        from agent_sre.sdlc.development_gates import (
            CommandEvidence,
            DevelopmentGatePolicy,
        )
        from agent_sre.sdlc.enterprise_gates import (
            EffectiveProjectPolicy,
            EnterpriseGateEvaluator,
            EnterpriseGatePolicy,
            HumanApproval,
            ReadinessStatus,
            effective_project_policy,
            issue_release_bundle,
            load_readiness_bundle,
            write_readiness_bundle,
        )
        from agent_sre.sdlc.enterprise_gates import (
            verify_release_bundle as verify_enterprise_release_bundle,
        )
        from agent_sre.sdlc.evaluator import load_release_policy
        from agent_sre.sdlc.orchestration import OrchestrationManifest, OrchestrationPolicy
        from agent_sre.sdlc.orchestration_runtime import ExecutionReceipt
        from agent_sre.sdlc.pyrit import load_pyrit_security_evidence
        from agent_sre.sdlc.risk import RiskClassification

        def load_model(path: str, model_type: Any) -> Any:
            payload = load_json_file_strict(path)
            return model_type.model_validate_json(canonical_json_bytes(payload), strict=True)

        def load_effective_policy(arguments: Any) -> EffectiveProjectPolicy:
            organization_enterprise = load_model(
                arguments.organization_enterprise_policy,
                EnterpriseGatePolicy,
            )
            organization_development = load_model(
                arguments.organization_development_policy,
                DevelopmentGatePolicy,
            )
            organization_orchestration = load_model(
                arguments.organization_orchestration_policy,
                OrchestrationPolicy,
            )
            organization_release = (
                load_release_policy(arguments.organization_release_policy)
                if arguments.organization_release_policy
                else None
            )
            project_enterprise = (
                load_model(arguments.project_enterprise_policy, EnterpriseGatePolicy)
                if arguments.project_enterprise_policy
                else organization_enterprise
            )
            project_development = (
                load_model(arguments.project_development_policy, DevelopmentGatePolicy)
                if arguments.project_development_policy
                else organization_development
            )
            project_orchestration = (
                load_model(arguments.project_orchestration_policy, OrchestrationPolicy)
                if arguments.project_orchestration_policy
                else organization_orchestration
            )
            project_release = (
                load_release_policy(arguments.project_release_policy)
                if arguments.project_release_policy
                else organization_release
            )
            return effective_project_policy(
                organization_enterprise=organization_enterprise,
                project_enterprise=project_enterprise,
                organization_development=organization_development,
                project_development=project_development,
                organization_orchestration=organization_orchestration,
                project_orchestration=project_orchestration,
                organization_release=organization_release,
                project_release=project_release,
            )

        if parsed.sdlc_command == "evaluate":
            try:
                change = load_model(parsed.change, ChangePackage)
                orchestration_manifest = load_model(
                    parsed.orchestration_manifest, OrchestrationManifest
                )
                execution_receipt = load_model(parsed.execution_receipt, ExecutionReceipt)
                execution_evidence = [load_model(path, CommandEvidence) for path in parsed.evidence]
                approvals = [load_model(path, HumanApproval) for path in parsed.approval]
                effective = load_effective_policy(parsed)
                pyrit_evidence = (
                    load_pyrit_security_evidence(parsed.pyrit_evidence)
                    if parsed.pyrit_evidence
                    else None
                )
                risk_classification = load_model(
                    parsed.risk_classification,
                    RiskClassification,
                )
                evaluated_at = (
                    datetime.fromisoformat(parsed.evaluated_at.replace("Z", "+00:00"))
                    if parsed.evaluated_at
                    else None
                )
                evaluator = EnterpriseGateEvaluator.from_effective_policy(effective)
                bundle = evaluator.evaluate_readiness(
                    change=change,
                    evidence=execution_evidence,
                    orchestration_manifest=orchestration_manifest,
                    execution_receipt=execution_receipt,
                    pyrit_evidence=pyrit_evidence,
                    risk_classification=risk_classification,
                    approvals=approvals,
                    evaluated_at=evaluated_at,
                )
                write_readiness_bundle(parsed.output, bundle)
                sys.stdout.buffer.write(canonical_json_bytes(bundle) + b"\n")
                return 0 if bundle.status is ReadinessStatus.READY else 1
            except Exception as exc:
                print(f"enterprise SDLC evaluation error: {exc}", file=sys.stderr)
                return 2

        if parsed.sdlc_command == "issue":
            from agent_sre.signing import ArtifactSigner

            try:
                bundle = load_readiness_bundle(parsed.readiness)
                change = load_model(parsed.change, ChangePackage)
                orchestration_manifest = load_model(
                    parsed.orchestration_manifest, OrchestrationManifest
                )
                execution_receipt = load_model(parsed.execution_receipt, ExecutionReceipt)
                execution_evidence = [load_model(path, CommandEvidence) for path in parsed.evidence]
                approvals = [load_model(path, HumanApproval) for path in parsed.approval]
                effective = load_effective_policy(parsed)
                pyrit_evidence = (
                    load_pyrit_security_evidence(parsed.pyrit_evidence)
                    if parsed.pyrit_evidence
                    else None
                )
                risk_classification = load_model(
                    parsed.risk_classification,
                    RiskClassification,
                )
                issuance = issue_release_bundle(
                    parsed.output,
                    bundle,
                    change=change,
                    effective_policy=effective,
                    trusted_change_digest=parsed.trusted_change_digest,
                    trusted_effective_policy_digest=parsed.trusted_effective_policy_digest,
                    evidence=execution_evidence,
                    orchestration_manifest=orchestration_manifest,
                    execution_receipt=execution_receipt,
                    pyrit_evidence=pyrit_evidence,
                    risk_classification=risk_classification,
                    approvals=approvals,
                    signer=ArtifactSigner(private_key_path=parsed.signing_key),
                    signer_did=parsed.signer_did,
                    signature_path=parsed.signature_output,
                )
                print(
                    json.dumps(
                        {
                            "bundle": str(issuance.bundle_path),
                            "signature": str(issuance.signature_path),
                            "readiness_digest": issuance.sidecar.readiness_digest,
                        },
                        sort_keys=True,
                    )
                )
                return 0
            except Exception as exc:
                print(f"enterprise SDLC issuance error: {exc}", file=sys.stderr)
                return 2

        if parsed.sdlc_command == "verify":
            from agent_sre.sdlc.signing import load_trusted_public_key

            try:
                trusted_key = load_trusted_public_key(parsed.trusted_public_key)
                expected_change = load_model(parsed.expected_change, ChangePackage)
                expected_orchestration_manifest = load_model(
                    parsed.expected_orchestration_manifest,
                    OrchestrationManifest,
                )
                expected_execution_receipt = load_model(
                    parsed.expected_execution_receipt,
                    ExecutionReceipt,
                )
                effective = load_effective_policy(parsed)
                valid = verify_enterprise_release_bundle(
                    parsed.bundle,
                    parsed.signature,
                    trusted_public_key=trusted_key,
                    expected_change=expected_change,
                    expected_orchestration_manifest=expected_orchestration_manifest,
                    expected_execution_receipt=expected_execution_receipt,
                    effective_policy=effective,
                    trusted_change_digest=parsed.trusted_change_digest,
                    trusted_effective_policy_digest=parsed.trusted_effective_policy_digest,
                )
                print(json.dumps({"verified": valid}, sort_keys=True))
                return 0 if valid else 1
            except Exception as exc:
                print(f"enterprise SDLC verification error: {exc}", file=sys.stderr)
                return 2

        sdlc_parser.print_help()
        return 1

    parser.print_help()
    return 1
