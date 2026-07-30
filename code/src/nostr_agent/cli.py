"""NostrAgent CLI -- identity, delegation, attestation, trust, L402, and demo.

Entry point: nostr-agent (via pyproject.toml scripts)
Environment variables:
    NOSTR_AGENT_RELAYS       Comma-separated relay URLs (default: ws://localhost:7771,ws://localhost:7772,ws://localhost:7773)
    NOSTR_AGENT_SECRET_KEY   Operator/agent hex secret key
    NOSTR_AGENT_LND_HOST     LND host (default: localhost)
    NOSTR_AGENT_LND_PORT     LND port (default: 10009)
    NOSTR_AGENT_LND_MACAROON Path to LND admin macaroon
    NOSTR_AGENT_LND_CERT     Path to LND TLS cert
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

app = typer.Typer(
    name="nostr-agent",
    help="NostrAgent: decentralized identity, delegation, and attestation for sovereign agents.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

# ---------------------------------------------------------------------------
# Environment-based defaults
# ---------------------------------------------------------------------------

_DEFAULT_RELAYS = os.environ.get(
    "NOSTR_AGENT_RELAYS",
    "ws://localhost:7771,ws://localhost:7772,ws://localhost:7773",
)
_DEFAULT_SECRET_KEY = os.environ.get("NOSTR_AGENT_SECRET_KEY", "")
_DEFAULT_LND_HOST = os.environ.get("NOSTR_AGENT_LND_HOST", "localhost")
_DEFAULT_LND_PORT = int(os.environ.get("NOSTR_AGENT_LND_PORT", "10009"))
_DEFAULT_LND_MACAROON = os.environ.get("NOSTR_AGENT_LND_MACAROON", "")
_DEFAULT_LND_CERT = os.environ.get("NOSTR_AGENT_LND_CERT", "")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _relay_list(relays: str) -> list[str]:
    return [r.strip() for r in relays.split(",") if r.strip()]


def _short(hex_key: str) -> str:
    if len(hex_key) > 16:
        return f"{hex_key[:8]}...{hex_key[-4:]}"
    return hex_key


def _ok(msg: str) -> None:
    console.print(f"[green]SUCCESS[/green] {msg}")


def _fail(msg: str) -> None:
    console.print(f"[red]FAILED[/red] {msg}")


def _warn(msg: str) -> None:
    console.print(f"[yellow]WARNING[/yellow] {msg}")


def _info(msg: str) -> None:
    console.print(f"[blue]>[/blue] {msg}")


def _step(n: int, total: int, label: str) -> None:
    console.print(Panel(f"[bold cyan]Step {n}/{total}[/bold cyan]  {label}", expand=False))


def _spinner(label: str) -> Progress:
    return Progress(SpinnerColumn(), TextColumn(f"[cyan]{label}[/cyan]"), transient=True)


def _run_async(coro):
    """Run an async coroutine from a sync CLI callback."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def _require_secret_key(sk_hex: str) -> "ns.Keys":
    """Parse a hex secret key into nostr_sdk Keys, or exit with error."""
    import nostr_sdk as ns
    if not sk_hex:
        console.print(
            "[red]Error:[/red] No secret key provided. "
            "Set NOSTR_AGENT_SECRET_KEY or pass the key as an option."
        )
        raise typer.Exit(1)
    try:
        sk = ns.SecretKey.parse(sk_hex)
        return ns.Keys(sk)
    except Exception as exc:
        console.print(f"[red]Error:[/red] Invalid secret key: {exc}")
        raise typer.Exit(1)


# ===========================================================================
# identity subcommands
# ===========================================================================

identity_app = typer.Typer(help="Manage agent identities (Kind 38100).")
app.add_typer(identity_app, name="identity")


@identity_app.command("create")
def identity_create(
    name: Annotated[str, typer.Option("--name", "-n", help="Human-readable agent name.")],
    d_tag: Annotated[str, typer.Option("--d-tag", "-d", help="Agent identifier (immutable).")],
    description: Annotated[str, typer.Option("--description", help="Agent purpose.")] = "NostrAgent instance",
    capabilities: Annotated[str, typer.Option("--capabilities", "-c", help="Comma-separated capabilities.")] = "",
    relays: Annotated[str, typer.Option("--relays", "-r", help="Comma-separated relay URLs. Env: NOSTR_AGENT_RELAYS")] = _DEFAULT_RELAYS,
    version: Annotated[str, typer.Option("--version", "-v", help="Semver version string.")] = "1.0.0",
    secret_key: Annotated[str, typer.Option("--secret-key", help="Operator hex secret key. Env: NOSTR_AGENT_SECRET_KEY")] = _DEFAULT_SECRET_KEY,
) -> None:
    """Create and publish a Kind 38100 Agent Identity Declaration."""
    from nostr_agent.identity import AgentIdentity

    caps = [c.strip() for c in capabilities.split(",") if c.strip()]
    relay_list = _relay_list(relays)
    operator_keys = _require_secret_key(secret_key)

    if not caps:
        console.print("[red]Error:[/red] At least one capability is required (--capabilities).")
        raise typer.Exit(1)

    console.print(Panel(f"[bold]Creating identity:[/bold] [yellow]{name}[/yellow]  d-tag={d_tag}", expand=False))

    async def _create():
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name=name,
            d_tag=d_tag,
            description=description,
            capabilities=caps,
            relay_urls=relay_list,
            version=version,
        )
        result = await identity.publish()
        return identity, result

    with _spinner("Creating identity and publishing to relays..."):
        try:
            identity, result = _run_async(_create())
        except Exception as exc:
            _fail(f"Identity creation failed: {exc}")
            raise typer.Exit(1)

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_row("[dim]pubkey[/dim]", f"[yellow]{identity.pubkey_hex}[/yellow]")
    t.add_row("[dim]d-tag[/dim]", d_tag)
    t.add_row("[dim]name[/dim]", name)
    t.add_row("[dim]version[/dim]", version)
    t.add_row("[dim]capabilities[/dim]", ", ".join(caps))
    t.add_row("[dim]next_key_hash[/dim]", f"[dim]{identity.next_key_hash}[/dim]")
    t.add_row("[dim]event_id[/dim]", result.event_id)
    t.add_row("[dim]relays (ok)[/dim]", f"[green]{', '.join(result.succeeded)}[/green]")
    if result.failed:
        t.add_row("[dim]relays (fail)[/dim]", f"[red]{result.failed}[/red]")
    console.print(t)
    _ok(f"Identity published to {result.success_count} relay(s).")


@identity_app.command("show")
def identity_show(
    d_tag: Annotated[str, typer.Option("--d-tag", "-d", help="Agent identifier.")] = "",
    pubkey: Annotated[str, typer.Option("--pubkey", "-p", help="Agent pubkey (hex).")] = "",
    relays: Annotated[str, typer.Option("--relays", "-r", help="Comma-separated relay URLs.")] = _DEFAULT_RELAYS,
) -> None:
    """Resolve and display a Kind 38100 agent identity."""
    from nostr_agent.discovery import RelayDiscovery, _parse_agent_info

    if not d_tag and not pubkey:
        console.print("[red]Error:[/red] Provide --d-tag or --pubkey (or both).")
        raise typer.Exit(1)

    relay_list = _relay_list(relays)

    async def _resolve():
        discovery = RelayDiscovery(relay_list)
        if d_tag:
            event = await discovery.resolve(d_tag=d_tag, pubkey=pubkey or None)
            if event is None:
                return None
            return _parse_agent_info(event)
        else:
            # pubkey-only: query by author
            from nostr_agent.discovery import fetch_identity
            ident = await fetch_identity(relay_list, pubkey)
            return ident

    with _spinner("Resolving identity from relays..."):
        try:
            info = _run_async(_resolve())
        except Exception as exc:
            _fail(f"Resolution failed: {exc}")
            raise typer.Exit(1)

    if info is None:
        _warn("No active identity found matching the query.")
        raise typer.Exit(0)

    t = Table(title="Agent Identity", show_lines=True)
    t.add_column("Field", style="cyan")
    t.add_column("Value")

    # Handle both AgentInfo (dataclass) and legacy AgentIdentity
    if hasattr(info, "name"):
        t.add_row("pubkey", getattr(info, "pubkey", ""))
        t.add_row("d-tag", getattr(info, "d_tag", ""))
        t.add_row("name", getattr(info, "name", ""))
        t.add_row("description", getattr(info, "description", ""))
        caps = getattr(info, "capabilities", ())
        t.add_row("capabilities", ", ".join(caps) if caps else "(none)")
        t.add_row("status", getattr(info, "status", "unknown"))
        t.add_row("operator", getattr(info, "operator_pubkey", ""))
        rurls = getattr(info, "relay_urls", ())
        t.add_row("relays", ", ".join(rurls) if rurls else "(none)")
        endpoints = getattr(info, "endpoints", {})
        if endpoints:
            t.add_row("endpoints", json.dumps(endpoints))
        tp = getattr(info, "trust_policy", None)
        if tp:
            t.add_row("trust_policy", f"decay={tp.trust_decay_per_hop}, depth={tp.max_trust_depth}, require_l402={tp.require_l402}")
    else:
        # Legacy AgentIdentity from types.py
        t.add_row("pubkey", str(getattr(info, "pubkey", "")))
        t.add_row("relays", ", ".join(str(r) for r in getattr(info, "relay_urls", [])))
        t.add_row("next_key_hash", getattr(info, "next_key_hash", ""))

    console.print(t)


@identity_app.command("rotate")
def identity_rotate(
    d_tag: Annotated[str, typer.Option("--d-tag", "-d", help="Agent d-tag to rotate.")],
    new_secret_key: Annotated[str, typer.Option("--new-key", help="Hex secret key matching pre-rotation commitment.")],
    relays: Annotated[str, typer.Option("--relays", "-r", help="Comma-separated relay URLs.")] = _DEFAULT_RELAYS,
    secret_key: Annotated[str, typer.Option("--secret-key", help="Current operator hex secret key.")] = _DEFAULT_SECRET_KEY,
    grace_period: Annotated[int, typer.Option("--grace-period", help="Seconds old delegations remain valid.")] = 3600,
) -> None:
    """Execute key rotation for a Kind 38100 identity."""
    import nostr_sdk as ns
    from nostr_agent.identity import AgentIdentity
    from nostr_agent.discovery import RelayDiscovery

    relay_list = _relay_list(relays)
    operator_keys = _require_secret_key(secret_key)

    console.print(Panel(f"[bold]Key Rotation[/bold] for d-tag=[yellow]{d_tag}[/yellow]", expand=False))

    async def _rotate():
        # First resolve the current identity
        discovery = RelayDiscovery(relay_list)
        event = await discovery.resolve(d_tag=d_tag)
        if event is None:
            raise ValueError(f"No active identity found for d-tag={d_tag}")

        # Parse the event content to reconstruct the identity
        content = json.loads(event.content())

        identity = AgentIdentity(
            keys=operator_keys,
            operator_pubkey=operator_keys.public_key(),
            d_tag=d_tag,
            name=content.get("name", ""),
            version=content.get("version", "1.0.0"),
            description=content.get("description", ""),
            capabilities=content.get("capabilities", []),
            relay_urls=relay_list,
        )
        # Restore pre-rotation state from the event
        for tag in event.tags().to_vec():
            vec = tag.as_vec()
            if vec and vec[0] == "next_key_hash" and len(vec) > 1:
                identity._next_key_hash = vec[1]

        new_sk = ns.SecretKey.parse(new_secret_key)
        next_next_keys = ns.Keys.generate()

        result = await identity.rotate(
            new_secret_key=new_sk,
            next_next_public_key=next_next_keys.public_key(),
            relay_urls=relay_list,
            grace_period=grace_period,
        )
        return result

    with _spinner("Executing 3-step key rotation..."):
        try:
            result = _run_async(_rotate())
        except Exception as exc:
            _fail(f"Key rotation failed: {exc}")
            raise typer.Exit(1)

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_row("[dim]old pubkey[/dim]", f"[red]{_short(result.old_pubkey)}[/red]")
    t.add_row("[dim]new pubkey[/dim]", f"[green]{_short(result.new_pubkey)}[/green]")
    t.add_row("[dim]timestamp[/dim]", str(result.rotation_timestamp))
    t.add_row("[dim]delegations reissued[/dim]", str(result.delegations_reissued))
    t.add_row("[dim]grace period[/dim]", f"{result.grace_period}s")
    console.print(t)
    _ok("Key rotation complete. Pre-rotation commitment verified.")


# ===========================================================================
# delegate command
# ===========================================================================

@app.command("delegate")
def delegate(
    to: Annotated[str, typer.Option("--to", help="Delegatee pubkey (hex).")],
    capabilities: Annotated[str, typer.Option("--capabilities", "-c", help="Comma-separated capabilities.")],
    depth: Annotated[int, typer.Option("--depth", help="Max chain depth.")] = 2,
    expires: Annotated[str, typer.Option("--expires", help="Expiry: e.g. 24h, 7d, or Unix timestamp.")] = "24h",
    relays: Annotated[str, typer.Option("--relays", "-r", help="Comma-separated relay URLs.")] = _DEFAULT_RELAYS,
    secret_key: Annotated[str, typer.Option("--secret-key", help="Operator hex secret key.")] = _DEFAULT_SECRET_KEY,
    d_tag: Annotated[str, typer.Option("--d-tag", "-d", help="Delegator identity d-tag.")] = "",
) -> None:
    """Create and publish a Kind 38101 Delegation Chain event."""
    from nostr_agent.delegation import DelegationManager
    from nostr_agent.identity import AgentIdentity
    from nostr_agent.types import Constraints, Scope

    caps = [c.strip() for c in capabilities.split(",") if c.strip()]
    relay_list = _relay_list(relays)
    operator_keys = _require_secret_key(secret_key)

    if not caps:
        console.print("[red]Error:[/red] At least one capability is required.")
        raise typer.Exit(1)

    # Parse expiry
    now = int(time.time())
    expires_at = _parse_expiry(expires, now)

    console.print(Panel("[bold]Delegation[/bold]", expand=False))
    _info(f"Delegatee    : {_short(to)}")
    _info(f"Capabilities : {caps}")
    _info(f"Max depth    : {depth}")
    _info(f"Expires at   : {time.strftime('%Y-%m-%d %H:%M', time.localtime(expires_at))}")

    scope = Scope(
        capabilities=tuple(sorted(caps)),
        resources=(),
        actions=(),
    )
    constraints = Constraints(
        expires_at=expires_at,
        max_chain_depth=depth,
        current_depth=1,
        issued_at=now,
    )

    async def _delegate():
        # Build a minimal identity for the delegator
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="cli-delegator",
            d_tag=d_tag or "cli-delegator",
            description="CLI delegation source",
            capabilities=caps,
            relay_urls=relay_list,
            version="1.0.0",
        )
        manager = DelegationManager(identity)
        result = await manager.delegate(
            delegatee_pubkey=to,
            scope=scope,
            constraints=constraints,
            parent_event=None,
            relay_urls=relay_list,
        )
        return result

    with _spinner("Signing and publishing delegation..."):
        try:
            result = _run_async(_delegate())
        except Exception as exc:
            _fail(f"Delegation failed: {exc}")
            raise typer.Exit(1)

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_row("[dim]event_id[/dim]", result.event_id)
    t.add_row("[dim]delegatee[/dim]", _short(to))
    t.add_row("[dim]capabilities[/dim]", ", ".join(caps))
    t.add_row("[dim]relays (ok)[/dim]", f"[green]{', '.join(result.succeeded)}[/green]")
    if result.failed:
        t.add_row("[dim]relays (fail)[/dim]", f"[red]{result.failed}[/red]")
    console.print(t)
    _ok("Delegation published.")


def _parse_expiry(expires: str, now: int) -> int:
    """Parse a duration string (24h, 7d, 30m) or Unix timestamp into an absolute timestamp."""
    expires = expires.strip()
    # Try as Unix timestamp first
    if expires.isdigit() and int(expires) > 1_000_000_000:
        return int(expires)
    # Parse duration
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if expires and expires[-1] in multipliers and expires[:-1].isdigit():
        return now + int(expires[:-1]) * multipliers[expires[-1]]
    # Default: treat as hours
    try:
        return now + int(expires) * 3600
    except ValueError:
        console.print(f"[red]Error:[/red] Cannot parse expiry: {expires!r}. Use e.g. 24h, 7d, or Unix timestamp.")
        raise typer.Exit(1)


# ===========================================================================
# attest command
# ===========================================================================

@app.command("attest")
def attest(
    agent: Annotated[str, typer.Option("--agent", help="Subject agent pubkey (hex).")],
    capability: Annotated[str, typer.Option("--capability", help="Capability being attested.")],
    confidence: Annotated[float, typer.Option("--confidence", help="Trust value in [0.0, 1.0].")] = 0.8,
    agent_d_tag: Annotated[str, typer.Option("--agent-d-tag", help="Subject agent d-tag.")] = "",
    context: Annotated[str, typer.Option("--context", help="Human-readable attestation context.")] = "",
    relays: Annotated[str, typer.Option("--relays", "-r", help="Comma-separated relay URLs.")] = _DEFAULT_RELAYS,
    secret_key: Annotated[str, typer.Option("--secret-key", help="Attester hex secret key.")] = _DEFAULT_SECRET_KEY,
) -> None:
    """Publish a Kind 38102 Peer Attestation event."""
    from nostr_agent.identity import AgentIdentity
    from nostr_agent.trust import TrustManager

    if not 0.0 <= confidence <= 1.0:
        console.print("[red]Error:[/red] --confidence must be in [0.0, 1.0].")
        raise typer.Exit(1)

    relay_list = _relay_list(relays)
    attester_keys = _require_secret_key(secret_key)

    console.print(Panel("[bold]Peer Attestation[/bold]", expand=False))
    _info(f"Subject      : {_short(agent)}")
    _info(f"Capability   : {capability}")
    _info(f"Confidence   : {confidence:.2f}")

    async def _attest():
        identity = await AgentIdentity.create(
            operator_keys=attester_keys,
            agent_name="cli-attester",
            d_tag="cli-attester",
            description="CLI attestation source",
            capabilities=[capability],
            relay_urls=relay_list,
            version="1.0.0",
        )
        manager = TrustManager(identity)
        result = await manager.attest(
            attestee_pubkey=agent,
            attestee_d_tag=agent_d_tag,
            capability=capability,
            confidence=confidence,
            context=context or None,
            relay_urls=relay_list,
        )
        return identity, result

    with _spinner("Signing and publishing attestation..."):
        try:
            identity, result = _run_async(_attest())
        except Exception as exc:
            _fail(f"Attestation failed: {exc}")
            raise typer.Exit(1)

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_row("[dim]event_id[/dim]", result.event_id)
    t.add_row("[dim]attester[/dim]", _short(identity.pubkey_hex))
    t.add_row("[dim]attestee[/dim]", _short(agent))
    t.add_row("[dim]capability[/dim]", capability)
    t.add_row("[dim]confidence[/dim]", f"{confidence:.2f}")
    t.add_row("[dim]relays (ok)[/dim]", f"[green]{', '.join(result.succeeded)}[/green]")
    console.print(t)
    _ok("Attestation published.")


# ===========================================================================
# trust command
# ===========================================================================

@app.command("trust")
def trust_cmd(
    source: Annotated[str, typer.Option("--source", help="Source pubkey (hex).")],
    target: Annotated[str, typer.Option("--target", help="Target pubkey (hex).")],
    capability: Annotated[str, typer.Option("--capability", help="Capability to evaluate.")] = "",
    decay: Annotated[float, typer.Option("--decay", help="Trust decay per hop.")] = 0.5,
    max_depth: Annotated[int, typer.Option("--max-depth", help="Maximum traversal depth.")] = 4,
    relays: Annotated[str, typer.Option("--relays", "-r", help="Comma-separated relay URLs.")] = _DEFAULT_RELAYS,
) -> None:
    """Compute trust score from source to target using bounded-sum aggregation."""
    from nostr_agent.trust import TrustManager, compute_trust_detailed

    relay_list = _relay_list(relays)

    console.print(Panel("[bold]Trust Query[/bold]", expand=False))
    _info(f"Source       : {_short(source)}")
    _info(f"Target       : {_short(target)}")
    _info(f"Capability   : {capability or '(all)'}")
    _info(f"Parameters   : decay={decay}, max_depth={max_depth}")

    async def _compute():
        if capability:
            graph = await TrustManager.build_trust_graph(capability, relay_list)
            result = TrustManager.compute_trust(
                graph, source, target,
                decay=decay, max_depth=max_depth,
            )
            return result, len(graph.adjacency)
        else:
            # Without capability filter, fetch all attestations and build raw graph
            from nostr_agent.trust import build_trust_graph, compute_trust_detailed as _compute_detailed
            import nostr_sdk as ns
            ns.uniffi_set_event_loop(asyncio.get_running_loop())
            from datetime import timedelta
            client = ns.Client()
            for url in relay_list:
                await client.add_relay(ns.RelayUrl.parse(url) if isinstance(url, str) else url)
            await client.connect()
            try:
                f = ns.Filter().kind(ns.Kind(38102))
                events = await client.fetch_events(f, timedelta(seconds=10))
            finally:
                await client.disconnect()
            raw = []
            for ev in events.to_vec():
                try:
                    content = json.loads(ev.content())
                except (json.JSONDecodeError, TypeError):
                    content = {}
                raw.append({
                    "pubkey": ev.author().to_hex(),
                    "created_at": ev.created_at().as_secs(),
                    "content": content,
                    "tags": [[t.as_vec()[0], *t.as_vec()[1:]] for t in ev.tags().to_vec() if t.as_vec()],
                })
            graph = build_trust_graph(raw)
            result = _compute_detailed(graph, source, target, decay=decay, max_depth=max_depth)
            return result, len(graph)

    with _spinner("Fetching attestation graph and computing trust..."):
        try:
            result, node_count = _run_async(_compute())
        except Exception as exc:
            _fail(f"Trust computation failed: {exc}")
            raise typer.Exit(1)

    score_color = "green" if result.score > 0.3 else ("yellow" if result.score > 0.1 else "red")

    t = Table(title="Trust Query Result", show_lines=True)
    t.add_column("Field", style="cyan")
    t.add_column("Value")
    t.add_row("source", _short(source))
    t.add_row("target", _short(target))
    t.add_row("capability", capability or "(all)")
    t.add_row("graph nodes", str(node_count))
    t.add_row("paths found", str(result.paths_found))
    t.add_row("paths pruned", str(result.paths_pruned))
    t.add_row("[bold]trust score[/bold]", f"[bold {score_color}]{result.score:.4f}[/bold {score_color}]")
    console.print(t)
    _info("Bounded-sum: trust(A,B) = 1 - prod(1 - path_i),  d={decay} per hop")


# ===========================================================================
# l402 command
# ===========================================================================

@app.command("l402")
def l402_cmd(
    url: Annotated[str, typer.Option("--url", help="Service endpoint URL.")],
    method: Annotated[str, typer.Option("--method", help="HTTP method.")] = "GET",
    max_pay: Annotated[int, typer.Option("--max-pay", help="Maximum payment in satoshis.")] = 100,
    lnd_host: Annotated[str, typer.Option("--lnd-host", help="LND gRPC host. Env: NOSTR_AGENT_LND_HOST")] = _DEFAULT_LND_HOST,
    lnd_port: Annotated[int, typer.Option("--lnd-port", help="LND gRPC port. Env: NOSTR_AGENT_LND_PORT")] = _DEFAULT_LND_PORT,
    lnd_macaroon: Annotated[str, typer.Option("--lnd-macaroon", help="Path to LND admin macaroon. Env: NOSTR_AGENT_LND_MACAROON")] = _DEFAULT_LND_MACAROON,
    lnd_cert: Annotated[str, typer.Option("--lnd-cert", help="Path to LND TLS cert. Env: NOSTR_AGENT_LND_CERT")] = _DEFAULT_LND_CERT,
    secret_key: Annotated[str, typer.Option("--secret-key", help="Agent hex secret key.")] = _DEFAULT_SECRET_KEY,
) -> None:
    """Perform an L402-gated request: challenge -> pay -> access (TB3)."""
    from nostr_agent.identity import AgentIdentity
    from nostr_agent.l402 import L402Client

    operator_keys = _require_secret_key(secret_key)
    relay_list = _relay_list(_DEFAULT_RELAYS)

    console.print(Panel("[bold]L402 Request[/bold]", expand=False))
    _info(f"Endpoint     : {url}")
    _info(f"Method       : {method}")
    _info(f"Max payment  : {max_pay} sats")
    _info(f"LND          : {lnd_host}:{lnd_port}")

    async def _l402_flow():
        identity = await AgentIdentity.create(
            operator_keys=operator_keys,
            agent_name="cli-l402",
            d_tag="cli-l402",
            description="CLI L402 client",
            capabilities=["l402-payment"],
            relay_urls=relay_list,
            version="1.0.0",
        )
        client = L402Client(
            identity=identity,
            lnd_host=lnd_host,
            lnd_port=lnd_port,
            lnd_macaroon_path=lnd_macaroon or None,
            lnd_tls_cert_path=lnd_cert or None,
            max_auto_pay_sat=max_pay,
        )

        _info("Step 1: Sending initial request with identity header...")
        await client.connect_lnd()
        _info("Step 2: LND connected, executing L402 flow...")
        response = await client.request_with_l402(
            method=method,
            url=url,
            max_amount_sat=max_pay,
        )
        return response

    with _spinner("Executing L402 payment flow..."):
        try:
            response = _run_async(_l402_flow())
        except Exception as exc:
            _fail(f"L402 flow failed: {exc}")
            raise typer.Exit(1)

    status_color = "green" if response.status_code < 400 else "red"
    _info(f"Step 3: Response received, status=[{status_color}]{response.status_code}[/{status_color}]")

    if response.status_code < 400:
        _ok("L402 request succeeded.")
    else:
        _warn(f"Response status: {response.status_code}")

    # Show response body (truncated)
    body = response.text[:2000]
    console.print(Panel(f"[dim]{body}[/dim]", title="Response Body", expand=False))


# ===========================================================================
# demo command -- runs the 5-agent scenario
# ===========================================================================

DEMO_SCENARIOS = {"full", "identity", "delegation", "trust"}


@app.command("demo")
def demo(
    scenario: Annotated[
        str,
        typer.Option("--scenario", "-s", help="Demo scenario: full, identity, delegation, trust."),
    ] = "full",
    pause: Annotated[float, typer.Option("--pause", help="Seconds to pause between steps.")] = 0.2,
) -> None:
    """Run a scripted demo sequence using the 5-agent deployment (C1-C5)."""
    if scenario not in DEMO_SCENARIOS:
        console.print(f"[red]Unknown scenario:[/red] {scenario}. Choose from: {sorted(DEMO_SCENARIOS)}")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"[bold cyan]NostrAgent Demo[/bold cyan] -- scenario: [yellow]{scenario}[/yellow]\n"
            "Decentralized Identity / Delegation / Attestation / L402",
            expand=False,
        )
    )

    # Import the deploy_5agent step functions
    from nostr_agent.deploy_5agent import (
        step1_generate_keypairs,
        step2_publish_identities,
        step3_build_delegation_chains,
        step4_publish_attestations,
        step5_verify_chains,
        step6_compute_trust,
        step7_revocation_cascade,
        step8_key_rotation,
        RELAY_DEFAULT,
    )

    if scenario == "full":
        total = 8
        _step(1, total, "Generate BIP340 Schnorr keypairs")
        agents = step1_generate_keypairs()
        time.sleep(pause)

        _step(2, total, "Publish Kind 38100 Agent Identity Declarations")
        step2_publish_identities(agents, RELAY_DEFAULT)
        time.sleep(pause)

        _step(3, total, "Build Kind 38101 Delegation Chains (with attenuation)")
        chains = step3_build_delegation_chains(agents)
        time.sleep(pause)

        _step(4, total, "Publish Kind 38102 Peer Attestations")
        raw_events = step4_publish_attestations(agents)
        time.sleep(pause)

        _step(5, total, "Verify delegation chains + spoofing rejection")
        step5_verify_chains(chains, agents)
        time.sleep(pause)

        _step(6, total, "Compute trust scores (bounded-sum / noisy-OR)")
        step6_compute_trust(raw_events, agents)
        time.sleep(pause)

        _step(7, total, "Revocation cascade: decommission weather agent")
        step7_revocation_cascade(agents)
        time.sleep(pause)

        _step(8, total, "Key rotation: operator key rotate (pre-rotation commitment)")
        step8_key_rotation(agents)

    elif scenario == "identity":
        total = 2
        _step(1, total, "Generate BIP340 Schnorr keypairs")
        agents = step1_generate_keypairs()
        time.sleep(pause)

        _step(2, total, "Publish Kind 38100 Agent Identity Declarations")
        step2_publish_identities(agents, RELAY_DEFAULT)

    elif scenario == "delegation":
        total = 4
        _step(1, total, "Generate BIP340 Schnorr keypairs")
        agents = step1_generate_keypairs()
        time.sleep(pause)

        _step(2, total, "Publish Kind 38100 Agent Identity Declarations")
        step2_publish_identities(agents, RELAY_DEFAULT)
        time.sleep(pause)

        _step(3, total, "Build Kind 38101 Delegation Chains (with attenuation)")
        chains = step3_build_delegation_chains(agents)
        time.sleep(pause)

        _step(4, total, "Publish Kind 38102 Peer Attestations")
        step4_publish_attestations(agents)

    elif scenario == "trust":
        total = 3
        _step(1, total, "Generate keypairs and identities")
        agents = step1_generate_keypairs()
        step2_publish_identities(agents, RELAY_DEFAULT)
        time.sleep(pause)

        _step(2, total, "Publish Kind 38102 Peer Attestations")
        raw_events = step4_publish_attestations(agents)
        time.sleep(pause)

        _step(3, total, "Compute trust scores (bounded-sum / noisy-OR)")
        step6_compute_trust(raw_events, agents)

    console.print(
        Panel(
            "[bold green]Demo complete.[/bold green]\n"
            "All 5 contributions (C1-C5) exercised: identity, delegation, attestation, "
            "trust aggregation, L402 payment.",
            expand=False,
        )
    )


# ===========================================================================
# config command
# ===========================================================================

@app.command("config")
def config_show() -> None:
    """Show active configuration (environment variables and defaults)."""
    t = Table(title="Active Configuration", show_lines=True)
    t.add_column("Variable", style="cyan")
    t.add_column("Value")
    t.add_column("Source", style="dim")

    def _row(name: str, value: str, default: str) -> None:
        source = "env" if os.environ.get(name) else "default"
        display = value if value else "(not set)"
        t.add_row(name, display, source)

    _row("NOSTR_AGENT_RELAYS", _DEFAULT_RELAYS, "ws://localhost:7771,...")
    _row("NOSTR_AGENT_SECRET_KEY", "(set)" if _DEFAULT_SECRET_KEY else "(not set)", "")
    _row("NOSTR_AGENT_LND_HOST", _DEFAULT_LND_HOST, "localhost")
    _row("NOSTR_AGENT_LND_PORT", str(_DEFAULT_LND_PORT), "10009")
    _row("NOSTR_AGENT_LND_MACAROON", _DEFAULT_LND_MACAROON, "")
    _row("NOSTR_AGENT_LND_CERT", _DEFAULT_LND_CERT, "")

    console.print(t)


if __name__ == "__main__":
    app()
