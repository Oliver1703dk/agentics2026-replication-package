"""Kind 38100 Agent Identity Declaration -- full lifecycle.

Manages key generation, identity event construction, relay publication,
identity resolution, key rotation with pre-rotation commitment (SHA256 of
the next pubkey committed in Kind 38100), and decommissioning.

The d-tag is immutable across rotations -- identity continuity survives
cryptographic key changes.

Reference: paper Section 4 (Kind 38100 schema, key rotation with pre-rotation).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import struct
import time
from datetime import timedelta

import nostr_sdk as ns  # type: ignore[import]

from nostr_agent.crypto import (
    compute_rotation_proof,
    generate_keypair,
    sha256,
    verify_schnorr,
)
from nostr_agent.types import (
    AgentIdentity as LegacyAgentIdentity,
    DecommissionResult,
    PublicKey,
    PublishError,
    PublishResult,
    RelayUrl,
    RotationError,
    RotationResult,
    Scope,
    TrustPolicy,
    VerificationResult,
    VerificationStatus,
)
from nostr_agent.validation import (
    validate_capabilities,
    validate_d_tag,
    validate_description,
    validate_name,
    validate_relay_urls,
    validate_version,
)

logger = logging.getLogger(__name__)

KIND_AGENT_IDENTITY = 38100

# Maximum rotation chain depth for verification walks.
MAX_ROTATION_DEPTH = 4

# Default relay query timeout.
_RELAY_TIMEOUT = timedelta(seconds=10)


# ============================================================================
# AgentIdentity -- the gateway class
# ============================================================================


class AgentIdentity:
    """Kind 38100 Agent Identity Declaration lifecycle.

    Encapsulates key generation, identity event construction, relay publication,
    identity resolution, key rotation with pre-rotation commitment, and
    decommissioning.

    The d-tag is immutable across rotations -- identity continuity survives
    cryptographic key changes.
    """

    def __init__(
        self,
        keys: ns.Keys,
        operator_pubkey: ns.PublicKey,
        d_tag: str,
        name: str,
        version: str,
        description: str,
        capabilities: list[str],
        relay_urls: list[str],
        trust_policy: TrustPolicy | None = None,
        endpoints: dict[str, str] | None = None,
    ) -> None:
        """Initialize identity state (does not publish).

        Args:
            keys: Agent's current BIP340 keypair.
            operator_pubkey: Operator's x-only public key (p-tag and content.operator).
            d_tag: Agent identifier. Regex: ^[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]$.
            name: Human-readable agent name (1-128 chars).
            version: Semver string (^[0-9]+.[0-9]+.[0-9]+$).
            description: Agent purpose (1-512 chars).
            capabilities: Capability labels. Each ^[a-z0-9-]{1,64}$. At least one.
            relay_urls: Preferred relay WebSocket URLs. At least one. Max 10.
            trust_policy: Trust evaluation parameters. Defaults applied if None.
            endpoints: Protocol endpoint URLs (keys: mcp, a2a, http, ws, custom).

        Raises:
            ValueError: If any input fails validation.
        """
        # --- Validate inputs ---
        if not validate_d_tag(d_tag):
            raise ValueError(
                f"Invalid d_tag: must match ^[a-z0-9][a-z0-9._-]{{0,126}}[a-z0-9]$, got {d_tag!r}"
            )
        if not validate_name(name):
            raise ValueError(f"Invalid name: must be 1-128 non-empty chars, got {name!r}")
        if not validate_version(version):
            raise ValueError(f"Invalid version: must be semver (X.Y.Z), got {version!r}")
        if not validate_description(description):
            raise ValueError(f"Invalid description: must be 1-512 chars, got {description!r}")
        if not validate_capabilities(capabilities):
            raise ValueError(
                f"Invalid capabilities: need >=1, each ^[a-z0-9-]{{1,64}}$, got {capabilities!r}"
            )
        if not validate_relay_urls(relay_urls):
            raise ValueError(
                f"Invalid relay_urls: need 1-10 wss?:// URLs, got {relay_urls!r}"
            )

        self._keys = keys
        self._operator_pubkey = operator_pubkey
        self._d_tag = d_tag
        self._name = name
        self._version = version
        self._description = description
        self._capabilities = list(capabilities)
        self._relay_urls = list(relay_urls)
        self._trust_policy = trust_policy or TrustPolicy()
        self._endpoints = dict(endpoints) if endpoints else {}

        # Identity lifecycle state.
        self._status: str = "active"
        self._published_event: ns.Event | None = None
        self._created_at: int = int(time.time())

        # Pre-rotation state.
        self._next_key_hash: str = ""
        self._next_secret_key: ns.SecretKey | None = None
        self._next_keys: ns.Keys | None = None

        # Rotation linkage (set on rotated identities).
        self._prev_key: str | None = None
        self._rotation_proof: str | None = None

    # --- Read-only properties ---

    @property
    def keys(self) -> ns.Keys:
        return self._keys

    @property
    def pubkey_hex(self) -> str:
        return self._keys.public_key().to_hex()

    @property
    def operator_pubkey(self) -> ns.PublicKey:
        return self._operator_pubkey

    @property
    def d_tag(self) -> str:
        return self._d_tag

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    @property
    def description(self) -> str:
        return self._description

    @property
    def capabilities(self) -> list[str]:
        return list(self._capabilities)

    @property
    def relay_urls(self) -> list[str]:
        return list(self._relay_urls)

    @property
    def trust_policy(self) -> TrustPolicy:
        return self._trust_policy

    @property
    def endpoints(self) -> dict[str, str]:
        return dict(self._endpoints)

    @property
    def status(self) -> str:
        return self._status

    @property
    def next_key_hash(self) -> str:
        return self._next_key_hash

    @property
    def published_event(self) -> ns.Event | None:
        return self._published_event

    # ------------------------------------------------------------------
    # create() -- class factory
    # ------------------------------------------------------------------

    @classmethod
    async def create(
        cls,
        operator_keys: ns.Keys,
        agent_name: str,
        d_tag: str,
        description: str,
        capabilities: list[str],
        relay_urls: list[str],
        version: str = "1.0.0",
        trust_policy: TrustPolicy | None = None,
        endpoints: dict[str, str] | None = None,
        next_public_key: ns.PublicKey | None = None,
    ) -> AgentIdentity:
        """Create a new agent identity with pre-rotation commitment.

        Generates a new keypair for the agent (separate from the operator keypair).
        If next_public_key is not provided, generates one and stores it internally.
        Computes next_key_hash = SHA256(next_public_key) for the pre-rotation tag.

        Does NOT publish -- call publish() after creation.

        Args:
            operator_keys: Operator's keypair (signs the identity event, goes in p-tag).
            agent_name: Human-readable name.
            d_tag: Agent identifier (immutable across rotations).
            description: Agent purpose.
            capabilities: Capability labels (become t-tags and content.capabilities).
            relay_urls: Preferred relays (become relay tags).
            version: Agent software version string.
            trust_policy: Trust policy parameters.
            endpoints: Protocol endpoint URLs.
            next_public_key: Pre-generated next public key. If None, a new keypair is
                generated and the next secret key is stored for future rotation.

        Returns:
            AgentIdentity instance ready for publication.

        Raises:
            ValueError: If d_tag, capabilities, or relay_urls fail validation.
        """
        # Generate the agent's keypair (distinct from operator).
        agent_keys = ns.Keys.generate()

        # Build the identity instance (validates inputs in __init__).
        identity = cls(
            keys=agent_keys,
            operator_pubkey=operator_keys.public_key(),
            d_tag=d_tag,
            name=agent_name,
            version=version,
            description=description,
            capabilities=capabilities,
            relay_urls=relay_urls,
            trust_policy=trust_policy,
            endpoints=endpoints,
        )

        # Pre-rotation: generate or accept the next key.
        if next_public_key is not None:
            nk_bytes = bytes.fromhex(next_public_key.to_hex())
            identity._next_key_hash = hashlib.sha256(nk_bytes).hexdigest()
        else:
            next_keys = ns.Keys.generate()
            identity._next_keys = next_keys
            identity._next_secret_key = next_keys.secret_key()
            nk_bytes = bytes.fromhex(next_keys.public_key().to_hex())
            identity._next_key_hash = hashlib.sha256(nk_bytes).hexdigest()

        return identity

    # ------------------------------------------------------------------
    # build_event() -- construct the Kind 38100 EventBuilder
    # ------------------------------------------------------------------

    def build_event(self) -> ns.EventBuilder:
        """Build the Kind 38100 event (unsigned).

        Constructs the full event with all required tags and JSON content.

        Returns:
            EventBuilder ready for signing / publishing.
        """
        tags: list[ns.Tag] = []

        # 1. d-tag (NIP-33 identifier)
        tags.append(ns.Tag.identifier(self._d_tag))

        # 2. p-tag (operator pubkey)
        tags.append(ns.Tag.public_key(self._operator_pubkey))

        # 3. t-tags (capability labels for relay-level #t filtering)
        for cap in self._capabilities:
            tags.append(ns.Tag.hashtag(cap))

        # 4. relay tags (single-letter "r")
        for url in self._relay_urls:
            tags.append(
                ns.Tag.custom(
                    ns.TagKind.SINGLE_LETTER(
                        ns.SingleLetterTag.lowercase(ns.Alphabet.R)
                    ),
                    [url],
                )
            )

        # 5. alt tag (NIP-31 human-readable fallback)
        if self._status == "rotated":
            alt_text = f"NostrAgent identity: {self._name} ({self._d_tag}) [ROTATED]"
        elif self._status == "decommissioned":
            alt_text = f"NostrAgent identity: {self._name} ({self._d_tag}) [DECOMMISSIONED]"
        else:
            alt_text = f"NostrAgent identity: {self._name} ({self._d_tag})"
        tags.append(ns.Tag.alt(alt_text))

        # 6. schema_version
        tags.append(ns.Tag.custom(ns.TagKind.UNKNOWN("schema_version"), ["1.0"]))

        # 7. next_key_hash (pre-rotation commitment) -- required on creation/rotation,
        #    optional on decommission.
        if self._next_key_hash:
            tags.append(
                ns.Tag.custom(ns.TagKind.UNKNOWN("next_key_hash"), [self._next_key_hash])
            )

        # 8. prev_key (rotation linkage -- present only on rotated-to events)
        if self._prev_key is not None:
            tags.append(
                ns.Tag.custom(ns.TagKind.UNKNOWN("prev_key"), [self._prev_key])
            )

        # --- Build content JSON ---
        content: dict = {
            "name": self._name,
            "version": self._version,
            "description": self._description,
            "status": self._status,
            "capabilities": self._capabilities,
            "endpoints": self._endpoints,
            "trust_policy": {
                "min_attestation_count": self._trust_policy.min_attestation_count,
                "trust_decay_per_hop": self._trust_policy.trust_decay_per_hop,
                "max_trust_depth": self._trust_policy.max_trust_depth,
                "require_l402": self._trust_policy.require_l402,
            },
            "operator": self._operator_pubkey.to_hex(),
            "created": self._created_at,
        }

        # rotation_proof goes in content only for post-rotation active events.
        if self._rotation_proof is not None:
            content["rotation_proof"] = self._rotation_proof

        content_json = json.dumps(content, separators=(",", ":"), ensure_ascii=True)

        builder = ns.EventBuilder(ns.Kind(KIND_AGENT_IDENTITY), content_json).tags(tags)
        # Pin the event-level created_at to match content.created so relay
        # parameterized-replaceable ordering and verification Rule 20 both pass.
        builder = builder.custom_created_at(ns.Timestamp.from_secs(self._created_at))
        return builder

    # ------------------------------------------------------------------
    # publish() -- sign and push to relays
    # ------------------------------------------------------------------

    async def publish(self, relay_urls: list[str] | None = None) -> PublishResult:
        """Sign and publish the Kind 38100 event to relays.

        Args:
            relay_urls: Additional relays beyond the preferred set. Optional.

        Returns:
            PublishResult with event_id, succeeded relay URLs, failed relay URLs.

        Raises:
            PublishError: If zero relays accepted the event.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        all_relays = list(self._relay_urls)
        if relay_urls:
            for url in relay_urls:
                if url not in all_relays:
                    all_relays.append(url)

        builder = self.build_event()

        signer = ns.NostrSigner.keys(self._keys)
        client = ns.Client(signer)
        try:
            for url in all_relays:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()

            output = await client.send_event_builder(builder)
        finally:
            await client.disconnect()

        succeeded = [str(r) for r in output.success]
        failed = {str(k): str(v) for k, v in output.failed.items()}

        if not succeeded:
            raise PublishError(
                f"Zero relays accepted the event. Failures: {failed}"
            )

        event_id = output.id.to_hex()

        # Store the signed event locally for later reference.
        # Re-sign locally so we have the Event object.
        self._published_event = builder.sign_with_keys(self._keys)

        result = PublishResult(
            event_id=event_id,
            succeeded=tuple(succeeded),
            failed=failed,
        )
        logger.info(
            "Published Kind 38100 (d=%s, status=%s) to %d/%d relays, id=%s",
            self._d_tag,
            self._status,
            len(succeeded),
            len(all_relays),
            event_id[:16],
        )
        return result

    # ------------------------------------------------------------------
    # rotate() -- 3-step atomic key rotation
    # ------------------------------------------------------------------

    async def rotate(
        self,
        new_secret_key: ns.SecretKey,
        next_next_public_key: ns.PublicKey,
        relay_urls: list[str] | None = None,
        grace_period: int = 3600,
    ) -> RotationResult:
        """Execute 3-step atomic key rotation.

        Step 1: Validate preconditions (status==active, SHA256(new_pk)==next_key_hash).
        Step 2: Compute rotation_proof = BIP340_sign(sk_new, SHA256(pk_old||pk_new||ts_be)).
        Step 3: Publish old key "rotated" event + new key "active" event.

        Args:
            new_secret_key: Secret key whose public key matches the pre-rotation commitment.
            next_next_public_key: Public key for the NEXT rotation (new pre-rotation commitment).
            relay_urls: Override relay set. Defaults to preferred relays.
            grace_period: Seconds old delegations remain valid (default 3600).

        Returns:
            RotationResult with old/new pubkeys, timestamp, delegations re-issued count.

        Raises:
            RotationError: If preconditions fail or relay publication fails critically.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        # --- Step 1: Validate preconditions ---
        if self._status != "active":
            raise RotationError(
                f"Cannot rotate: identity status is {self._status!r}, must be 'active'"
            )
        if not self._next_key_hash:
            raise RotationError("Cannot rotate: no next_key_hash pre-rotation commitment")

        new_keys = ns.Keys(new_secret_key)
        new_pk_hex = new_keys.public_key().to_hex()
        new_pk_bytes = bytes.fromhex(new_pk_hex)

        # Verify pre-rotation commitment: SHA256(new_pk_bytes) must equal next_key_hash.
        actual_hash = hashlib.sha256(new_pk_bytes).hexdigest()
        if actual_hash != self._next_key_hash:
            raise RotationError(
                f"Pre-rotation mismatch: SHA256(new_pk)={actual_hash} != "
                f"committed next_key_hash={self._next_key_hash}"
            )

        old_pk_hex = self.pubkey_hex
        old_pk_bytes = bytes.fromhex(old_pk_hex)
        # Ensure rotation timestamp is strictly after original publish to satisfy
        # relay parameterized replaceable semantics (latest created_at wins).
        rotation_ts = max(int(time.time()), self._created_at + 1)

        # --- Step 2: Compute rotation proof ---
        # rotation_proof = BIP340_sign(sk_new, SHA256(pk_old || pk_new || created_at_be))
        sk_new_bytes = bytes.fromhex(new_secret_key.to_hex())
        rotation_proof_bytes = compute_rotation_proof(
            sk_new=sk_new_bytes,
            pk_old=old_pk_bytes,
            pk_new=new_pk_bytes,
            timestamp=rotation_ts,
        )
        rotation_proof_hex = rotation_proof_bytes.hex()

        # Compute next_next_key_hash for the new identity.
        nnk_bytes = bytes.fromhex(next_next_public_key.to_hex())
        next_next_key_hash = hashlib.sha256(nnk_bytes).hexdigest()

        # --- Step 3: Publish events ---
        target_relays = relay_urls if relay_urls else list(self._relay_urls)

        # 3a. Publish old-key "rotated" status event.
        self._status = "rotated"
        self._created_at = rotation_ts
        old_builder = self.build_event()

        signer_old = ns.NostrSigner.keys(self._keys)
        client_old = ns.Client(signer_old)
        try:
            for url in target_relays:
                await client_old.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client_old.connect()
            old_output = await client_old.send_event_builder(old_builder)
        finally:
            await client_old.disconnect()

        old_succeeded = [str(r) for r in old_output.success]
        if not old_succeeded:
            # Revert status -- rotation failed at first step.
            self._status = "active"
            raise RotationError(
                f"Failed to publish old-key rotated event. Failures: {old_output.failed}"
            )

        old_event_id = old_output.id.to_hex()

        # 3b. Build and publish new-key "active" identity event.
        new_identity = AgentIdentity(
            keys=new_keys,
            operator_pubkey=self._operator_pubkey,
            d_tag=self._d_tag,
            name=self._name,
            version=self._version,
            description=self._description,
            capabilities=self._capabilities,
            relay_urls=self._relay_urls,
            trust_policy=self._trust_policy,
            endpoints=self._endpoints,
        )
        new_identity._status = "active"
        new_identity._created_at = rotation_ts
        new_identity._next_key_hash = next_next_key_hash
        new_identity._prev_key = old_pk_hex
        new_identity._rotation_proof = rotation_proof_hex

        new_builder = new_identity.build_event()

        signer_new = ns.NostrSigner.keys(new_keys)
        client_new = ns.Client(signer_new)
        try:
            for url in target_relays:
                await client_new.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client_new.connect()
            new_output = await client_new.send_event_builder(new_builder)
        finally:
            await client_new.disconnect()

        new_succeeded = [str(r) for r in new_output.success]
        if not new_succeeded:
            raise RotationError(
                f"Published old-key rotated event but failed to publish new-key active event. "
                f"Failures: {new_output.failed}. Manual recovery required."
            )

        new_event_id = new_output.id.to_hex()
        new_identity._published_event = new_builder.sign_with_keys(new_keys)

        logger.info(
            "Rotated Kind 38100 (d=%s): %s -> %s, proof=%s",
            self._d_tag,
            old_pk_hex[:16],
            new_pk_hex[:16],
            rotation_proof_hex[:16],
        )

        return RotationResult(
            old_pubkey=old_pk_hex,
            new_pubkey=new_pk_hex,
            rotation_timestamp=rotation_ts,
            delegations_reissued=0,  # Delegation re-issuance handled by DelegationManager.
            grace_period=grace_period,
            old_event_id=old_event_id,
            new_event_id=new_event_id,
        )

    # ------------------------------------------------------------------
    # decommission() -- permanently retire identity
    # ------------------------------------------------------------------

    async def decommission(
        self, relay_urls: list[str] | None = None
    ) -> DecommissionResult:
        """Permanently retire the agent identity.

        Publishes Kind 38100 with status "decommissioned", no next_key_hash.
        All delegations immediately invalidated (no grace period).

        Args:
            relay_urls: Override relay set.

        Returns:
            DecommissionResult with pubkey and timestamp.

        Raises:
            PublishError: If zero relays accept the event.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        if self._status != "active":
            raise RotationError(
                f"Cannot decommission: identity status is {self._status!r}, must be 'active'"
            )

        decomm_ts = max(int(time.time()), self._created_at + 1)
        self._status = "decommissioned"
        self._created_at = decomm_ts
        # No next_key_hash on decommission -- strip it.
        self._next_key_hash = ""

        target_relays = relay_urls if relay_urls else list(self._relay_urls)
        builder = self.build_event()

        signer = ns.NostrSigner.keys(self._keys)
        client = ns.Client(signer)
        try:
            for url in target_relays:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()
            output = await client.send_event_builder(builder)
        finally:
            await client.disconnect()

        succeeded = [str(r) for r in output.success]
        failed = {str(k): str(v) for k, v in output.failed.items()}

        if not succeeded:
            # Revert status.
            self._status = "active"
            raise PublishError(
                f"Failed to publish decommission event. Failures: {failed}"
            )

        event_id = output.id.to_hex()
        self._published_event = builder.sign_with_keys(self._keys)

        logger.info(
            "Decommissioned Kind 38100 (d=%s, pk=%s), id=%s",
            self._d_tag,
            self.pubkey_hex[:16],
            event_id[:16],
        )

        return DecommissionResult(
            pubkey=self.pubkey_hex,
            timestamp=decomm_ts,
            event_id=event_id,
        )

    # ------------------------------------------------------------------
    # verify() -- static event verification
    # ------------------------------------------------------------------

    @staticmethod
    async def verify(event: ns.Event, relay_urls: list[str]) -> VerificationResult:
        """Verify a Kind 38100 event including rotation chain.

        Checks: NIP-01 validity, BIP340 signature, tag-level validation (30 rules),
        content-level validation, and if prev_key present: walk rotation chain to genesis.

        Args:
            event: The Kind 38100 event to verify.
            relay_urls: Relays to query for rotation chain predecessors (>= 2 recommended).

        Returns:
            VerificationResult with is_valid, status, chain_depth, errors list.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())
        errors: list[str] = []

        # --- NIP-01 checks ---
        # Rule 1-2: id and sig verification.
        if not event.verify():
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.INVALID_SIGNATURE,
                chain_depth=0,
                errors=("BIP340 signature verification failed",),
            )

        # Rule 3: kind check.
        if event.kind().as_u16() != KIND_AGENT_IDENTITY:
            errors.append(f"Expected kind {KIND_AGENT_IDENTITY}, got {event.kind().as_u16()}")

        # Rule 4: timestamp not >300s in the future.
        now = int(time.time())
        event_ts = event.created_at().as_secs()
        if event_ts > now + 300:
            errors.append(f"Timestamp {event_ts - now}s in the future exceeds 300s tolerance")

        # --- Tag-level checks ---
        tags = event.tags()

        # Rule 5: d-tag.
        d_tag_val = tags.identifier()
        if not d_tag_val or not validate_d_tag(d_tag_val):
            errors.append(f"Invalid or missing d-tag: {d_tag_val!r}")

        # Rule 6: p-tag (operator pubkey).
        p_tag = tags.find(ns.TagKind.SINGLE_LETTER(ns.SingleLetterTag.lowercase(ns.Alphabet.P)))
        if p_tag is None:
            errors.append("Missing required p-tag (operator pubkey)")
        else:
            p_vec = p_tag.as_vec()
            if len(p_vec) < 2 or len(p_vec[1]) != 64:
                errors.append(f"Invalid p-tag value: {p_vec}")

        # Rule 10: schema_version.
        sv_tag = tags.find(ns.TagKind.UNKNOWN("schema_version"))
        if sv_tag is None:
            errors.append("Missing required schema_version tag")
        else:
            sv_vec = sv_tag.as_vec()
            sv_val = sv_vec[1] if len(sv_vec) > 1 else ""
            if not sv_val.startswith("1."):
                errors.append(f"Unrecognized schema major version: {sv_val!r}")

        # Rule 11: next_key_hash format if present.
        nkh_tag = tags.find(ns.TagKind.UNKNOWN("next_key_hash"))
        nkh_val: str | None = None
        if nkh_tag is not None:
            nkh_vec = nkh_tag.as_vec()
            nkh_val = nkh_vec[1] if len(nkh_vec) > 1 else ""
            if len(nkh_val) != 64:
                errors.append(f"next_key_hash must be 64 hex chars, got {len(nkh_val)}")

        # Rule 12: prev_key format if present.
        pk_tag = tags.find(ns.TagKind.UNKNOWN("prev_key"))
        prev_key_val: str | None = None
        if pk_tag is not None:
            pk_vec = pk_tag.as_vec()
            prev_key_val = pk_vec[1] if len(pk_vec) > 1 else ""
            if len(prev_key_val) != 64:
                errors.append(f"prev_key must be 64 hex chars, got {len(prev_key_val)}")

        # --- Content-level checks ---
        try:
            content = json.loads(event.content())
        except (json.JSONDecodeError, Exception) as exc:
            errors.append(f"Content is not valid JSON: {exc}")
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.INVALID_SCHEMA,
                chain_depth=0,
                errors=tuple(errors),
            )

        # Rule 16: content size.
        content_bytes = event.content().encode("utf-8")
        if len(content_bytes) > 8192:
            errors.append(f"Content size {len(content_bytes)} bytes exceeds 8192 limit")

        # Rule 17: required content fields.
        for field_name in ("name", "version", "description", "status", "capabilities", "operator", "created"):
            if field_name not in content:
                errors.append(f"Missing required content field: {field_name!r}")

        # Rule 18: status enum.
        status = content.get("status", "")
        if status not in ("active", "rotated", "decommissioned"):
            errors.append(f"Invalid status: {status!r}")

        # Rule 19: operator == p-tag value.
        if p_tag is not None:
            p_hex = p_tag.as_vec()[1] if len(p_tag.as_vec()) > 1 else ""
            if content.get("operator", "") != p_hex:
                errors.append(
                    f"content.operator ({content.get('operator', '')!r}) != p-tag ({p_hex!r})"
                )

        # Rule 20: created == created_at.
        if content.get("created") != event_ts:
            errors.append(
                f"content.created ({content.get('created')}) != event created_at ({event_ts})"
            )

        # Early return on schema errors (before chain walk).
        if errors:
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.INVALID_SCHEMA,
                chain_depth=0,
                errors=tuple(errors),
            )

        # Check terminal states.
        if status == "decommissioned":
            return VerificationResult(
                is_valid=True,
                status=VerificationStatus.DECOMMISSIONED,
                chain_depth=0,
                errors=(),
            )

        if status == "rotated":
            return VerificationResult(
                is_valid=True,
                status=VerificationStatus.REVOKED,
                chain_depth=0,
                errors=(),
            )

        # --- Rotation chain verification (Rules 25-28) ---
        if prev_key_val is not None:
            chain_result = await _verify_rotation_chain(event, relay_urls)
            return chain_result

        # Genesis event, status active, all checks passed.
        return VerificationResult(
            is_valid=True,
            status=VerificationStatus.VALID,
            chain_depth=0,
            errors=(),
        )

    # ------------------------------------------------------------------
    # resolve() -- find active identity on relays
    # ------------------------------------------------------------------

    @staticmethod
    async def resolve(
        d_tag: str,
        relay_urls: list[str],
        pubkey: ns.PublicKey | None = None,
    ) -> ns.Event | None:
        """Resolve the current active Kind 38100 event for a d-tag.

        Queries >= 2 relays, groups by pubkey, finds status=="active" with latest
        created_at. Verifies rotation chain if prev_key present.

        Args:
            d_tag: Agent identifier to resolve.
            relay_urls: Relays to query (>= 2 recommended).
            pubkey: If provided, restricts search to this specific pubkey.

        Returns:
            The active Kind 38100 event, or None if not found / decommissioned.
        """
        ns.uniffi_set_event_loop(asyncio.get_running_loop())

        client = ns.Client()
        try:
            for url in relay_urls:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()

            f = ns.Filter().kind(ns.Kind(KIND_AGENT_IDENTITY)).identifier(d_tag)
            if pubkey is not None:
                f = f.author(pubkey)

            events = await client.fetch_events(f, _RELAY_TIMEOUT)
        finally:
            await client.disconnect()

        event_list = events.to_vec()
        if not event_list:
            return None

        # Find the active event with the latest created_at.
        best: ns.Event | None = None
        for ev in event_list:
            try:
                content = json.loads(ev.content())
            except (json.JSONDecodeError, Exception):
                continue

            if content.get("status") != "active":
                continue

            if best is None or ev.created_at().as_secs() > best.created_at().as_secs():
                best = ev

        if best is None:
            return None

        # Verify the event (including rotation chain if prev_key present).
        vr = await AgentIdentity.verify(best, relay_urls)
        if not vr.is_valid:
            logger.warning(
                "Resolved event for d=%s failed verification: %s", d_tag, vr.errors
            )
            return None

        return best


# ============================================================================
# Internal helpers
# ============================================================================


async def _verify_rotation_chain(
    event: ns.Event, relay_urls: list[str]
) -> VerificationResult:
    """Walk the prev_key chain back to genesis, verifying each hop.

    Implements key_rotation_protocol.md §4.1 algorithm.
    """
    current = event
    depth = 0

    while True:
        pk_tag = current.tags().find(ns.TagKind.UNKNOWN("prev_key"))
        if pk_tag is None:
            # Reached genesis -- verify it has no rotation_proof.
            try:
                genesis_content = json.loads(current.content())
            except Exception:
                return VerificationResult(
                    is_valid=False,
                    status=VerificationStatus.CHAIN_BROKEN,
                    chain_depth=depth,
                    errors=("Genesis event has invalid JSON content",),
                )
            if "rotation_proof" in genesis_content:
                return VerificationResult(
                    is_valid=False,
                    status=VerificationStatus.CHAIN_BROKEN,
                    chain_depth=depth,
                    errors=("Genesis event must not have rotation_proof",),
                )
            # Valid chain.
            return VerificationResult(
                is_valid=True,
                status=VerificationStatus.VALID,
                chain_depth=depth,
                errors=(),
            )

        depth += 1
        if depth > MAX_ROTATION_DEPTH:
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.CHAIN_BROKEN,
                chain_depth=depth,
                errors=(f"Rotation chain depth {depth} exceeds max {MAX_ROTATION_DEPTH}",),
            )

        prev_pk_vec = pk_tag.as_vec()
        prev_pk_hex = prev_pk_vec[1] if len(prev_pk_vec) > 1 else ""
        d_tag_val = current.tags().identifier() or ""

        # Query relays for predecessor event.
        predecessor = await _fetch_predecessor(prev_pk_hex, d_tag_val, relay_urls)
        if predecessor is None:
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.CHAIN_BROKEN,
                chain_depth=depth,
                errors=(f"Predecessor event not found for prev_key={prev_pk_hex[:16]}...",),
            )

        # Verify predecessor has next_key_hash.
        pred_nkh_tag = predecessor.tags().find(ns.TagKind.UNKNOWN("next_key_hash"))
        if pred_nkh_tag is None:
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.CHAIN_BROKEN,
                chain_depth=depth,
                errors=("Predecessor event missing next_key_hash tag",),
            )
        pred_nkh = pred_nkh_tag.as_vec()[1] if len(pred_nkh_tag.as_vec()) > 1 else ""

        # Verify pre-rotation: SHA256(current.pubkey) == predecessor.next_key_hash.
        current_pk_hex = current.author().to_hex()
        current_pk_bytes = bytes.fromhex(current_pk_hex)
        expected_hash = hashlib.sha256(current_pk_bytes).hexdigest()
        if expected_hash != pred_nkh:
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.CHAIN_BROKEN,
                chain_depth=depth,
                errors=(
                    f"Pre-rotation mismatch: SHA256(current_pk)={expected_hash} != "
                    f"predecessor.next_key_hash={pred_nkh}",
                ),
            )

        # Verify rotation_proof in current event's content.
        try:
            current_content = json.loads(current.content())
        except Exception:
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.CHAIN_BROKEN,
                chain_depth=depth,
                errors=("Current event has invalid JSON content",),
            )

        rotation_proof_hex = current_content.get("rotation_proof")
        if not rotation_proof_hex:
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.CHAIN_BROKEN,
                chain_depth=depth,
                errors=("Current event missing rotation_proof in content",),
            )

        # Verify BIP340 signature: verify_schnorr(pk_current, SHA256(pk_old||pk_new||ts_be), sig)
        current_ts = current.created_at().as_secs()
        msg = sha256(
            bytes.fromhex(prev_pk_hex)
            + current_pk_bytes
            + struct.pack(">Q", current_ts)
        )
        if not verify_schnorr(
            current_pk_bytes, msg, bytes.fromhex(rotation_proof_hex)
        ):
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.CHAIN_BROKEN,
                chain_depth=depth,
                errors=("Invalid rotation_proof BIP340 signature",),
            )

        # Verify predecessor status.
        try:
            pred_content = json.loads(predecessor.content())
        except Exception:
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.CHAIN_BROKEN,
                chain_depth=depth,
                errors=("Predecessor event has invalid JSON content",),
            )
        pred_status = pred_content.get("status", "")
        if pred_status not in ("rotated", "active"):
            return VerificationResult(
                is_valid=False,
                status=VerificationStatus.CHAIN_BROKEN,
                chain_depth=depth,
                errors=(f"Predecessor status is {pred_status!r}, expected 'rotated' or 'active'",),
            )

        # Continue walking the chain.
        current = predecessor


async def _fetch_predecessor(
    pubkey_hex: str, d_tag: str, relay_urls: list[str]
) -> ns.Event | None:
    """Fetch the predecessor Kind 38100 event by pubkey and d-tag."""
    client = ns.Client()
    try:
        for url in relay_urls:
            await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
        await client.connect()

        author_pk = ns.PublicKey.parse(pubkey_hex)
        f = (
            ns.Filter()
            .kind(ns.Kind(KIND_AGENT_IDENTITY))
            .author(author_pk)
            .identifier(d_tag)
        )
        events = await client.fetch_events(f, _RELAY_TIMEOUT)
    finally:
        await client.disconnect()

    event_list = events.to_vec()
    if not event_list:
        return None

    # Return the event with the highest created_at.
    return max(event_list, key=lambda e: e.created_at().as_secs())


# ============================================================================
# Module-level backward-compatibility helpers
# ============================================================================
# These are imported by discovery.py and other modules.


def compute_next_key_hash(next_pubkey_hex: str) -> str:
    """SHA256 of the next rotation key hex (pre-rotation commitment).

    Note: The spec says SHA256(pk_next_bytes) where pk_next_bytes is the 32-byte
    x-only pubkey. This function takes hex and hashes the raw bytes.
    """
    pk_bytes = bytes.fromhex(next_pubkey_hex)
    return hashlib.sha256(pk_bytes).hexdigest()


def build_identity_event(
    keys: ns.Keys,
    operator_pubkey: PublicKey,
    relay_urls: list[RelayUrl],
    scopes: list[Scope],
    next_key_hash: str,
) -> ns.Event:
    """Build and sign a Kind 38100 event (legacy interface).

    Retained for backward compatibility. New code should use AgentIdentity.build_event().
    """
    tags: list[ns.Tag] = [
        ns.Tag.public_key(ns.PublicKey.parse(operator_pubkey)),
        ns.Tag.custom(ns.TagKind.UNKNOWN("next_key_hash"), [next_key_hash]),
    ]
    for url in relay_urls:
        tags.append(
            ns.Tag.custom(
                ns.TagKind.SINGLE_LETTER(
                    ns.SingleLetterTag.lowercase(ns.Alphabet.R)
                ),
                [url],
            )
        )
    for s in scopes:
        for cap in s.capabilities:
            tags.append(ns.Tag.hashtag(cap))

    content = json.dumps(
        {"scopes": [{"capabilities": list(s.capabilities)} for s in scopes]},
        separators=(",", ":"),
    )
    builder = ns.EventBuilder(ns.Kind(KIND_AGENT_IDENTITY), content).tags(tags)
    return builder.sign_with_keys(keys)


def parse_identity_event(event: ns.Event) -> LegacyAgentIdentity:
    """Parse a Kind 38100 event into a legacy AgentIdentity dataclass.

    Retained for backward compatibility with discovery.py.
    """
    tags = event.tags()

    # Extract operator pubkey from p-tag.
    p_tag = tags.find(ns.TagKind.SINGLE_LETTER(ns.SingleLetterTag.lowercase(ns.Alphabet.P)))
    if p_tag is not None:
        p_vec = p_tag.as_vec()
        operator_pubkey = PublicKey(p_vec[1]) if len(p_vec) > 1 else PublicKey("")
    else:
        operator_pubkey = PublicKey("")

    # Extract next_key_hash.
    nkh_tag = tags.find(ns.TagKind.UNKNOWN("next_key_hash"))
    next_key_hash = ""
    if nkh_tag is not None:
        nkh_vec = nkh_tag.as_vec()
        next_key_hash = nkh_vec[1] if len(nkh_vec) > 1 else ""

    # Extract relay URLs from r-tags.
    relay_urls: list[RelayUrl] = []
    for tag in tags.to_vec():
        vec = tag.as_vec()
        if vec and vec[0] == "r" and len(vec) > 1:
            relay_urls.append(RelayUrl(vec[1]))

    # Extract scopes from content JSON or t-tags.
    scopes: list[Scope] = []
    try:
        content = json.loads(event.content())
        if "capabilities" in content:
            caps = tuple(content["capabilities"])
            scopes = [Scope(capabilities=caps)]
        elif "scopes" in content:
            for s in content["scopes"]:
                scopes.append(
                    Scope(capabilities=tuple(s.get("capabilities", ())))
                )
    except (json.JSONDecodeError, Exception):
        pass

    return LegacyAgentIdentity(
        pubkey=PublicKey(event.author().to_hex()),
        operator_pubkey=operator_pubkey,
        relay_urls=relay_urls,
        scopes=scopes,
        next_key_hash=next_key_hash,
        event_id=event.id().to_hex(),
        created_at=event.created_at().as_secs(),
    )
