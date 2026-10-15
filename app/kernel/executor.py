"""Public entry point of the deterministic kernel: draft, authorize, commit, cancel.

Out of the model's reach: the Agent's tool gateway can only call create_draft (a draft, no side effects).
authorize / commit can only be called by the frontend over HTTP after the user's own device has signed. Even then,
commit does not write to the ledger itself: it hands the signed instruction to the execution gateway
(app/bank/gateway.py), which verifies the signature again on its own before posting.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid

from app.bank.gateway import ExecutionGateway, GatewayError
from app.bank.mock_bank import MockBank
from app.config import settings
from app.kernel import crosscheck, p256, rules, webauthn
from app.kernel import changes, contract
from app.kernel import protection as prot
from app.kernel.audit import AuditLog
from app.kernel.credentials import CredentialRegistry
from app.kernel.evidence import confirmed_proposal, ground, user_utterances
from app.kernel.signing import (DEFAULT_SITE, MockAuthenticator, SignatureError, Site, TokenService,
                                build_challenge, build_settings_challenge, canonical, check_signature, compute_digest,
                                BIOMETRIC_REQUIRED, browser_key_allowed)
from app.kernel.state import Session
from app.models import Draft, Phase, RiskLevel, fmt_money


class KernelError(Exception):
    def __init__(self, message: str, code: str = "KERNEL_ERROR"):
        super().__init__(message)
        self.code = code


class Kernel:
    def __init__(self, bank: MockBank, audit: AuditLog, tokens: TokenService | None = None,
                 authenticator: MockAuthenticator | None = None, allow_mock: bool | None = None,
                 registry: CredentialRegistry | None = None, gateway: ExecutionGateway | None = None,
                 require_verification: bool = True, risk_hour: int | None = None):
        self.risk_hour = risk_hour  # injectable clock hour for isolated lab fixtures only
        self.bank = bank
        self.audit = audit
        self.tokens = tokens or TokenService()
        self.authenticator = authenticator or MockAuthenticator()
        # The demo-string authenticator is OFF unless explicitly allowed: payments need a device signature.
        self.allow_mock = (settings.auth_mode == "mock") if allow_mock is None else allow_mock
        self.registry = registry or CredentialRegistry()
        self.gateway = gateway or ExecutionGateway(bank, self.registry, audit, allow_unsigned=self.allow_mock)
        self.reviews = self.gateway.reviews
        # No independent-verifier verdict -> the draft can't be signed (fail closed)
        self.require_verification = require_verification

    # ------------------------------------------------------------------ Credentials
    def register_key(self, s: Session, jwk: dict) -> str:
        """Register the browser's public signing key for this session (once). Returns the key id."""
        if not browser_key_allowed(self.registry):
            raise KernelError(BIOMETRIC_REQUIRED, "BIOMETRIC_REQUIRED")
        try:
            p256.public_point(jwk)
        except p256.InvalidKey as e:
            raise KernelError(str(e), "INVALID_KEY") from e
        public = {k: jwk[k] for k in ("kty", "crv", "x", "y")}
        if s.public_key and s.public_key != public:
            raise KernelError("This session already has a different signing key.", "KEY_EXISTS")
        if not s.public_key:
            s.public_key = public
            self.registry.set_device_key(s.session_id, public)
            self.audit.append("device.key_registered", s.session_id, {"key_id": p256.key_fingerprint(public),
                                                                       "alg": "ECDSA P-256"})
        return p256.key_fingerprint(public)

    def passkey_status(self, user_id: str, site: Site) -> dict:
        keys = self.registry.passkeys(user_id, site.rp_id)
        return {"enrolled": bool(keys), "credential_ids": [k["credential_id"] for k in keys],
                "key_ids": [webauthn.key_id(k["public_key"]) for k in keys]}

    def passkey_options(self, s: Session, site: Site) -> dict:
        if self.registry.has_passkey(s.user_id):
            raise KernelError("Verify and remove your existing passkey before replacing it.", "PASSKEY_EXISTS")
        challenge = secrets.token_bytes(32)
        s.passkey_reg = {"challenge": webauthn.b64u(challenge), "expires_at": time.time() + settings.challenge_ttl,
                         "rp_id": site.rp_id}
        user = self.bank.user(s.user_id)
        return {"challenge": s.passkey_reg["challenge"], "rp_id": site.rp_id, "rp_name": "Star · DBS concept",
                "user_id": webauthn.b64u(hashlib.sha256(s.user_id.encode()).digest()[:16]),
                "user_name": s.user_id, "display_name": user["name"],
                "exclude": self.passkey_status(s.user_id, site)["credential_ids"]}

    def passkey_register(self, s: Session, site: Site, credential_id: str, client_data_json: str,
                         attestation_object: str) -> str:
        if self.registry.has_passkey(s.user_id):
            raise KernelError("An existing passkey cannot be replaced without verification.", "PASSKEY_EXISTS")
        reg = s.passkey_reg
        if not reg or reg["expires_at"] < time.time() or reg["rp_id"] != site.rp_id:
            raise KernelError("The fingerprint set-up expired. Please try again.", "EXPIRED")
        try:
            cred = webauthn.verify_registration(
                credential_id=credential_id, client_data_json=client_data_json, attestation_object=attestation_object,
                challenge=webauthn.unb64u(reg["challenge"]), rp_id=site.rp_id, origins=set(site.origins))
        except webauthn.WebAuthnError as e:
            raise KernelError(str(e), e.code) from e
        s.passkey_reg = None
        self.registry.add_passkey(s.user_id, cred)
        key_id = webauthn.key_id(cred["public_key"])
        self.audit.append("device.passkey_enrolled", s.session_id, {"key_id": key_id, "rp_id": site.rp_id,
                                                                     "alg": f"WebAuthn {cred['public_key'].get('alg', 'ES256')}, user verification required"})
        return key_id

    def passkey_remove_challenge(self, s: Session, site: Site) -> str:
        payload = build_settings_challenge(s.session_id, s.user_id, {"remove_passkeys": site.rp_id})
        s.setting_challenges["remove_passkeys"] = payload
        return payload

    def passkey_remove(self, s: Session, site: Site, assertion: dict | None = None) -> int:
        issued = s.setting_challenges.get("remove_passkeys")
        if not issued or not isinstance(assertion, dict) or assertion.get("payload") != issued:
            raise KernelError("Verify your identity before removing a passkey.", "AUTH_REQUIRED")
        if json.loads(issued)["expires_at"] < time.time():
            raise KernelError("This confirmation expired.", "EXPIRED")
        rec = self._signature(s, issued, assertion, site)
        if rec["method"] != "passkey":
            raise KernelError("An enrolled passkey is required.", "AUTH_REQUIRED")
        s.setting_challenges.pop("remove_passkeys", None)
        n = self.registry.remove_passkeys(s.user_id, site.rp_id)
        self.audit.append("device.passkey_removed", s.session_id, {"rp_id": site.rp_id, "count": n})
        return n

    def _signature(self, s: Session, payload: str, assertion: dict, site: Site) -> dict:
        try:
            rec = check_signature(self.registry, user_id=s.user_id, session_id=s.session_id, payload=payload,
                                  assertion=assertion, site=site)
        except SignatureError as e:
            raise KernelError(str(e), e.code) from e
        if rec["method"] == "passkey":
            self.registry.bump_count(s.user_id, site.rp_id, rec["credential_id"], rec.get("sign_count", 0))
        return rec

    # ------------------------------------------------------------------ Draft
    def create_draft(self, s: Session, *, kind: str, payee_id: str, amount_cents: int,
                     from_account: str | None = None, bill_id: str | None = None,
                     taint: list[str] | None = None, local_hour: int | None = None,
                     evidence: str = "", verification: dict | None = None, schedule: dict | None = None,
                     heard: tuple[str, str] | None = None) -> Draft:
        s.settle()
        if s.phase != Phase.IDLE:
            raise KernelError("There is already a payment waiting for confirmation. Please confirm or cancel it first.", "PENDING_DRAFT")
        from app.agent.request_guard import problem
        for utterance in s.task_utterances():
            error = problem(utterance)
            if error:
                raise KernelError(error, "REQUEST_UNSUPPORTED")
        accounts = self.bank.accounts(s.user_id)
        from_account = from_account or accounts[0]["account_id"]
        if kind == "investment":
            target = self.bank.product(payee_id)
            name, asset = (target["name"], target["asset_class"]) if target else ("(unknown product)", "Unknown")
        else:
            target = self.bank.payee(s.user_id, payee_id)
            name, asset = (target["name"] if target else "(unknown payee)"), "Cash"
        now = time.time()
        draft = Draft(
            draft_id="d_" + uuid.uuid4().hex[:10], user_id=s.user_id, kind=kind,
            from_account=from_account, payee_id=payee_id, payee_name=name, asset_class=asset,
            amount_cents=amount_cents, bill_id=bill_id, created_at=now,
            expires_at=now + settings.draft_ttl, nonce=secrets.token_hex(6), taint=taint or [], schedule=schedule,
            plan_id=s.plan_id)
        bill = self.bank.bill(s.user_id, bill_id) if bill_id else None
        g = ground(user_utterances(s.messages), target, amount_cents, kind, bill=bill, model_quote=evidence,
                   accounts=self.bank.accounts(s.user_id), from_account=from_account, heard=heard,
                   proposal=confirmed_proposal(s.messages))
        latest_user = next((m for m in reversed(s.messages) if m.get("role") == "user"), {})
        parent_id = latest_user.get("reference_parent_id")
        parent = next((r for r in s.receipts if parent_id and r.get("card", {}).get("draft_id") == parent_id), None)
        if parent and parent.get("status") == "SUCCESS" and parent["card"]["amount_cents"] == amount_cents * 2:
            g.amount_source = "derived"
            g.derived = f"Half of the signed transaction {parent_id}"
            g.quote = latest_user.get("raw_content", g.quote)[:160]
        # A model-planner step whose amount the code worked out ("half of it", "whatever is left"): the draft must use
        # exactly that number, and take the money from the account the plan resolved
        resolved = latest_user.get("resolved") or {}
        draft.dependency_ids = list(dict.fromkeys(([parent_id] if parent_id else []) + resolved.get("dependency_ids", [])))
        if resolved.get("from_account") and from_account != resolved["from_account"]:
            raise KernelError(f"This step's money comes from the {resolved['from_account']} account; draft it with "
                              f"from_account={resolved['from_account']}.", "WRONG_SOURCE")
        if resolved.get("amount_cents") is not None:
            if amount_cents == resolved["amount_cents"]:
                g.amount, g.amount_source, g.derived = True, "derived", resolved["why"]
            else:
                g.amount, g.amount_source = False, "derived mismatch"
                g.derived = f"{resolved['why']}, which is {fmt_money(resolved['amount_cents'])}"
            g.quote = latest_user.get("raw_content", g.quote)[:160]
        draft.grounding, draft.you_said = g.as_dict(), g.quote
        draft.digest = compute_digest(draft)
        level = prot.effective(self.bank, s.user_id, now)
        ctx = rules.RuleContext(now=now, scam_level=s.scam_level, scam_reasons=list(s.scam_reasons),
                                local_hour=local_hour if local_hour is not None else self.risk_hour, grounding=g, protection=level)
        draft.risk = rules.evaluate(draft, self.bank, ctx)

        # Dual-engine audit: compare with what the independent verifier heard (deterministic comparison)
        if verification is not None:
            draft.verification = {**crosscheck.compare(draft, verification.get("extracted") or {}, self.bank),
                                  "engine": verification.get("engine", "?"),
                                  "extracted": verification.get("extracted"),
                                  "parallel": verification.get("parallel", False)}
        elif self.require_verification:
            draft.verification = {"status": "missing", "mismatches": [], "fields": {}}

        s.drafts[draft.draft_id] = draft
        s.current_draft_id = draft.draft_id
        s.transition(Phase.DRAFTED)
        frozen = draft.verification.get("status") == "mismatch"
        if draft.risk.level == RiskLevel.BLOCK:
            s.transition(Phase.BLOCKED)
        elif frozen:
            s.transition(Phase.FROZEN)
        elif draft.risk.level == RiskLevel.HIGH:
            draft.cooling_until = now + draft.risk.cooldown_seconds
            s.transition(Phase.COOLING)
        else:
            s.transition(Phase.AWAITING_AUTH)

        s.add_trace("evidence", f"Grounded in the user's words: payee {'✓' if g.payee else '✗'} · "
                                f"amount {'✓' if g.amount else '✗'} ({g.amount_source})", g.as_dict())
        if draft.verification:
            v = draft.verification
            marks = " · ".join(f"{k} {'✓' if st == 'match' else '✗' if st == 'mismatch' else '–'}"
                               for k, st in v.get("fields", {}).items())
            s.add_trace("verify", f"Independent verifier ({v.get('engine', '-')}{', ran in parallel' if v.get('parallel') else ''}): "
                                  f"{'MISMATCH → frozen' if frozen else v['status'].upper()} · {marks}", v)
        s.add_trace("rule", f"Rule grading: {draft.risk.level.value} (protection: {level})",
                    {"hits": draft.risk.rule_hits, "ruleset": rules.RULESET_VERSION})
        self.audit.append("draft.created", s.session_id, {
            "draft": draft.card_fields(), "digest": draft.digest, "risk": draft.risk.model_dump(mode="json"),
            "grounding": draft.grounding, "verification": draft.verification, "protection": level,
            "ruleset": rules.RULESET_VERSION})
        if frozen:
            self.audit.append("draft.frozen", s.session_id, {"draft_id": draft.draft_id,
                                                             "mismatches": draft.verification["mismatches"]})
        self.record_decision(s, draft)
        return draft

    def record_decision(self, s, draft, **kwargs):
        result = contract.decision(draft, s, self.bank, self.reviews, **kwargs)
        draft.decision = result
        self.audit.append("contract.decision", s.session_id, result)
        return result

    def approve_secondary(self, s, draft_id, digest):
        """Only the authenticated demo-reviewer HTTP endpoint may call this; never an agent tool."""
        draft = self._get_draft(s, draft_id)
        if s.phase not in (Phase.COOLING, Phase.AWAITING_AUTH) or draft.expires_at <= time.time():
            raise KernelError("This draft is no longer awaiting approval.", "REVIEW_NOT_PENDING")
        if digest != draft.digest or compute_digest(draft) != digest:
            raise KernelError("Review is for a different card.", "DIGEST_MISMATCH")
        if draft.verification.get("status") != "match":
            raise KernelError("The intent check must pass first.", "NOT_VERIFIED")
        self._recheck_risk(s, draft)
        if not contract.secondary_required(draft.card_fields(), self.bank):
            raise KernelError("This payment does not need secondary approval.", "REVIEW_NOT_REQUIRED")
        rec = self.reviews.approve(s.user_id, s.session_id, draft_id, digest, draft.expires_at)
        try:
            self.audit.append("review.approved", s.session_id, rec)
            self.record_decision(s, draft)
        except Exception:
            self.reviews.revoke(s.session_id, draft_id)
            raise
        return rec

    def _contract_gate(self, s, draft, *, signature=False, verify_answer=False, stage="before_authorization"):
        record = self.record_decision(s, draft, signature=signature, verify_answer=verify_answer, stage=stage)
        if record["checks"]["plan"]["status"] == "fail":
            raise KernelError("An earlier transaction has not completed. Nothing can move.", "DEPENDENCY_NOT_COMPLETED")
        if record["checks"]["secondary_approval"]["status"] == "pending":
            raise KernelError("A separate demo reviewer must approve this exact payment first.", "SECONDARY_APPROVAL_REQUIRED")

    # ------------------------------------------------------------------ Challenge
    def issue_challenge(self, s: Session, draft_id: str, shown_digest: str,
                        verify_answer: bool | None = None) -> str:
        """Hand the device the exact bytes to sign. Issuing a new challenge invalidates the previous one."""
        draft = self._get_draft(s, draft_id)
        self._refresh_cooling(s, draft)
        self._precheck(s, draft, shown_digest, verify_answer)
        if not s.public_key and not self.registry.has_passkey(s.user_id):
            raise KernelError("This device has no registered signing key yet.", "NO_KEY")
        payload = build_challenge(s.session_id, draft)
        s.challenges[draft_id] = payload
        self.audit.append("auth.challenge_issued", s.session_id,
                          {"draft_id": draft_id, "payload_sha256": hashlib.sha256(payload.encode()).hexdigest()})
        return payload

    def _precheck(self, s: Session, draft: Draft, shown_digest: str, verify_answer: bool | None) -> None:
        if s.phase != Phase.AWAITING_AUTH:
            raise KernelError(self._phase_message(s, draft), "NOT_AWAITING_AUTH")
        if shown_digest != draft.digest or compute_digest(draft) != draft.digest:
            self.audit.append("auth.rejected", s.session_id, {"draft_id": draft.draft_id, "reason": "digest_mismatch"})
            raise KernelError("The confirmation card doesn't match the transaction. Rejected.", "DIGEST_MISMATCH")
        self._recheck_risk(s, draft)
        if self.require_verification and draft.verification.get("status") != "match":
            raise KernelError("The independent check hasn't confirmed this payment, so it can't be signed.",
                              "NOT_VERIFIED")
        if draft.risk and draft.risk.verify_question and verify_answer is not True:
            raise KernelError("Please answer the verification question first.", "VERIFY_REQUIRED")
        self._contract_gate(s, draft, verify_answer=verify_answer)

    # ------------------------------------------------------------------ Authorize
    def authorize(self, s: Session, draft_id: str, shown_digest: str, assertion,
                  verify_answer: bool | None = None, site: Site = DEFAULT_SITE) -> str:
        """assertion = a passkey assertion {"type": "webauthn", ...} or a browser-key {"payload", "signature"},
        over the exact challenge. (A demo string such as "demo-fingerprint" only when allow_mock is on.)"""
        draft = self._get_draft(s, draft_id)
        self._refresh_cooling(s, draft)
        self._precheck(s, draft, shown_digest, verify_answer)
        if isinstance(assertion, dict):
            method = self._verify_payment_signature(s, draft, assertion, site)
        elif self.allow_mock and isinstance(assertion, str) and self.authenticator.verify(assertion):
            method = "mock:" + assertion
        else:
            self.audit.append("auth.rejected", s.session_id, {"draft_id": draft_id, "reason": "no_valid_signature"})
            raise KernelError("A valid signature from your device is required.", "AUTH_FAILED")
        token = self.tokens.issue(draft_id, shown_digest)
        label = {"passkey": "Server verified the passkey: the device checked your fingerprint / face and signed the exact card",
                 "device_key": "Server verified the browser-key signature over the exact card (fingerprint simulated for the demo)"}.get(
            method, "User confirmed (demo authenticator)")
        s.add_trace("sign", label, {"digest": shown_digest[:16] + "…", "method": method})
        self.audit.append("auth.granted", s.session_id, {"draft_id": draft_id, "digest": shown_digest,
                                                         "method": method})
        self.record_decision(s, draft, stage="authorized", signature=isinstance(assertion, dict), verify_answer=True)
        return token

    def _verify_payment_signature(self, s: Session, draft: Draft, assertion: dict, site: Site) -> str:
        def reject(reason: str, code: str):
            self.audit.append("auth.rejected", s.session_id, {"draft_id": draft.draft_id, "reason": code})
            raise KernelError(reason, code)
        payload = assertion.get("payload")
        issued = s.challenges.get(draft.draft_id)
        if not issued or payload != issued:
            reject("The signed content isn't exactly what was shown to you. Rejected.", "PAYLOAD_MISMATCH")
        signed = json.loads(payload)
        if signed["expires_at"] < time.time():
            s.challenges.pop(draft.draft_id, None)
            reject("This confirmation expired. Please confirm again.", "EXPIRED")
        if (signed["session_id"] != s.session_id or signed["draft_id"] != draft.draft_id
                or signed["digest"] != draft.digest or signed["digest"] != compute_digest(draft)):
            reject("The payment changed after it was shown to you. Rejected.", "DRAFT_CHANGED")
        try:
            rec = self._signature(s, payload, assertion, site)
        except KernelError as e:
            reject(str(e), e.code)
        s.challenges.pop(draft.draft_id, None)          # single use
        s.signatures[draft.draft_id] = rec
        return rec["method"]

    # ------------------------------------------------------------------ Commit
    def commit(self, s: Session, draft_id: str, token: str) -> dict:
        draft = self._get_draft(s, draft_id)
        if s.phase != Phase.AWAITING_AUTH:
            raise KernelError(self._phase_message(s, draft), "NOT_AWAITING_AUTH")
        recomputed = compute_digest(draft)
        ok, why = self.tokens.verify_and_consume(token, draft_id, recomputed)
        if not ok:
            self.audit.append("commit.rejected", s.session_id, {"draft_id": draft_id, "reason": why})
            self.record_decision(s, draft, stage="rejected", rejection="TOKEN_INVALID")
            raise KernelError(why, "TOKEN_INVALID")
        # Re-run the rules before executing (the balance may have changed; prevents time-of-check vs time-of-use gaps)
        self._recheck_risk(s, draft)
        self._contract_gate(s, draft, signature=bool(s.signatures.get(draft_id)), verify_answer=True, stage="pre_execution")
        # The ledger is behind a zero-trust gateway that re-verifies the device signature itself
        try:
            receipt = self.gateway.execute(user_id=s.user_id, session_id=s.session_id, card=draft.card_fields(),
                                           digest=recomputed, auth=s.signatures.get(draft_id),
                                           idempotency_key=draft.draft_id,
                                           verification={k: draft.verification.get(k) for k in ("status", "fields", "engine")},
                                           decision=draft.decision)
        except GatewayError as e:
            s.transition(Phase.CANCELLED)
            self.record_decision(s, draft, stage="rejected", rejection=e.code)
            raise KernelError(str(e), e.code) from e
        receipt = dict(receipt)
        receipt.setdefault("verifiable", self._verifiable_receipt(s, draft, receipt))
        s.transition(Phase.EXECUTED)
        draft.decision = receipt.get("verifiable", {}).get("decision", draft.decision)
        self.reviews.revoke(s.session_id, draft_id)
        s.add_trace("gateway", "Execution gateway re-verified the device signature on its own, then " +
                    ("set up the standing instruction (DBS Standing Instructions · POST /standing-instructions)"
                     if draft.schedule else "posted to the ledger"),
                    {"txn_id": receipt["txn_id"]})
        s.add_trace("exec", f"Executed {fmt_money(draft.amount_cents)} → {draft.payee_name}",
                    {"txn_id": receipt["txn_id"]})
        # The signed ledger receipt and audit outbox were committed atomically with the debit.
        if not any(r["txn_id"] == receipt["txn_id"] for r in s.receipts):
            s.receipts.insert(0, receipt["verifiable"])

        return receipt

    def _recheck_risk(self, s: Session, draft: Draft) -> None:
        current = rules.evaluate(draft, self.bank, rules.RuleContext(
            scam_level=s.scam_level, scam_reasons=list(s.scam_reasons), local_hour=self.risk_hour,
            protection=prot.effective(self.bank, s.user_id)))
        old_hits = set(draft.risk.rule_hits if draft.risk else [])
        new_risk = current.level.rank > draft.risk.level.rank or bool(set(current.rule_hits) - old_hits)
        if current.level == RiskLevel.BLOCK or new_risk:
            s.challenges.pop(draft.draft_id, None)
            s.signatures.pop(draft.draft_id, None)
            s.transition(Phase.CANCELLED)
            draft.risk = current
            self.reviews.revoke(s.session_id, draft.draft_id)
            self.record_decision(s, draft, stage="rejected", rejection="RECHECK_BLOCKED")
            self.audit.append("commit.rejected", s.session_id,
                              {"draft_id": draft.draft_id, "reason": current.rule_hits})
            raise KernelError("The payment conditions changed. Please prepare and review a new payment.", "RECHECK_BLOCKED")

    def _verifiable_receipt(self, s: Session, draft: Draft, receipt: dict) -> dict:
        """A receipt anyone can check offline (scripts/verify_receipt.py): card -> digest -> signed payload -> key."""
        body = {"receipt_version": 2, "txn_id": receipt["txn_id"], "status": receipt["status"],
                "executed_at": int(receipt["executed_at"]), "card": draft.card_fields(), "digest": draft.digest,
                "verification": {k: draft.verification.get(k) for k in ("status", "fields", "engine")},
                "authorization": s.signatures.get(draft.draft_id) or {"method": "demo authenticator (unsigned)"}}
        body["receipt_sha256"] = hashlib.sha256(canonical(body).encode()).hexdigest()
        return body

    # ------------------------------------------------------------------ Signed account settings
    def protection_challenge(self, s: Session, to: str) -> str:
        if to != "standard":
            raise KernelError("Only lowering protection needs a signature.", "NOT_NEEDED")
        payload = build_settings_challenge(s.session_id, s.user_id, {"protection": to})
        s.setting_challenges["protection"] = payload
        return payload

    def change_protection(self, s: Session, to: str, assertion: dict | None = None, site: Site = DEFAULT_SITE) -> dict:
        if to == "enhanced":                          # raising (or cancelling a scheduled lowering) is instant
            st = prot.raise_now(self.bank, s.user_id)
            self.audit.append("settings.protection_raised", s.session_id, {"level": "enhanced"})
            return st
        if to != "standard":
            raise KernelError("Unknown protection level.", "BAD_REQUEST")
        issued = s.setting_challenges.get("protection")
        if not issued or not isinstance(assertion, dict) or assertion.get("payload") != issued:
            raise KernelError("Please confirm this change with your fingerprint.", "PAYLOAD_MISMATCH")
        if json.loads(issued)["expires_at"] < time.time():
            raise KernelError("This confirmation expired. Please try again.", "EXPIRED")
        rec = self._signature(s, issued, assertion, site)
        s.setting_challenges.pop("protection", None)
        st = prot.schedule_lowering(self.bank, s.user_id)
        self.audit.append("settings.protection_lowering_scheduled", s.session_id,
                          {"effective_at": st["pending"]["effective_at"] if st["pending"] else None,
                           "method": rec["method"], "key_id": rec["key_id"]})
        return st

    # ------------------------------------------------------------------ Account changes (kernel/changes.py)
    def _wrap(self, fn, *a):
        try:
            return fn(self, *a)
        except changes.ChangeError as e:
            raise KernelError(str(e), e.code) from e

    def request_change(self, s: Session, kind: str, data: dict, evidence: str = "") -> dict:
        return self._wrap(changes.request, s, kind, data, evidence)

    def change_challenge(self, s: Session, change_id: str) -> str:
        return self._wrap(changes.challenge, s, change_id)

    def apply_change(self, s: Session, change_id: str, assertion, site: Site = DEFAULT_SITE) -> dict:
        return self._wrap(changes.apply, s, change_id, assertion, site)

    def cancel_change(self, s: Session, change_id: str) -> None:
        return self._wrap(changes.cancel, s, change_id)

    def lower_limit(self, s: Session, cents: int) -> dict:
        return self._wrap(changes.lower_limit, s, cents)

    def cancel_standing_instruction(self, s: Session, si_id: str) -> dict:
        return self._wrap(changes.cancel_standing_instruction, s, si_id)

    def cancel_giro(self, s: Session, giro_id: str) -> dict:
        return self._wrap(changes.cancel_giro, s, giro_id)

    # ------------------------------------------------------------------ Cancel
    def cancel(self, s: Session, draft_id: str, reason: str = "user") -> None:
        draft = self._get_draft(s, draft_id)
        if s.phase in (Phase.DRAFTED, Phase.COOLING, Phase.AWAITING_AUTH, Phase.FROZEN):
            s.transition(Phase.CANCELLED)
            self.reviews.revoke(s.session_id, draft_id)
            self.record_decision(s, draft, stage="cancelled", rejection="Cancelled by user; nothing posted.")
            self.audit.append("draft.cancelled", s.session_id, {"draft_id": draft.draft_id, "reason": reason})

    # ------------------------------------------------------------------ Helpers
    def _get_draft(self, s: Session, draft_id: str) -> Draft:
        if s.current_draft_id != draft_id or draft_id not in s.drafts:
            raise KernelError("I can't find this pending payment.", "NO_SUCH_DRAFT")
        return s.drafts[draft_id]

    def _refresh_cooling(self, s: Session, draft: Draft) -> None:
        if s.phase == Phase.COOLING and time.time() >= draft.cooling_until:
            s.transition(Phase.AWAITING_AUTH)

    @staticmethod
    def _phase_message(s: Session, draft: Draft) -> str:
        if s.phase == Phase.COOLING:
            left = max(0, int(draft.cooling_until - time.time()))
            return f"Still in the cooling-off period. Please confirm in {left} seconds."
        if s.phase == Phase.BLOCKED:
            return "This payment was blocked and can't be made."
        if s.phase == Phase.FROZEN:
            return "This payment was frozen because it didn't match what you said."
        if s.phase == Phase.EXECUTED:
            return "This payment has already been made."
        return "This payment can't be confirmed right now."


__all__ = ["Kernel", "KernelError"]
