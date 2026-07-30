# nostr-sdk v0.44.2 Python Subscription Patterns

## Overview
nostr-sdk Python uses **two async patterns**: (1) `stream_events()` for one-shot auto-closing subscriptions, (2) `subscribe()` for long-lived subscriptions with callbacks. No event loop threading needed -- use `asyncio` exclusively.

## Pattern 1: HandleNotification Callback (Recommended for Real-Time)
Best for persistent monitoring of Identity/Delegation/Attestation events.

```python
from nostr_sdk import Client, Filter, Kind, HandleNotification, RelayOptions

class AgentEventListener(HandleNotification):
    """Custom callback handler for real-time Nostr events."""
    
    async def handle(self, relay_url: str, subscription_id: str, event):
        """Invoked when event arrives from relay."""
        if event.kind == Kind.CUSTOM_38100():  # Identity rotation
            print(f"[Identity] {event.d_tag} rotated at {relay_url}")
        elif event.kind == Kind.CUSTOM_38101():  # Delegation revocation
            print(f"[Delegation] Revocation for {event.p_tag}")
        elif event.kind == Kind.CUSTOM_38102():  # New attestation
            print(f"[Attestation] {event.author} vouches for {event.p_tag}")

async def main():
    client = Client()
    handler = AgentEventListener()
    
    # Add relay
    await client.add_relay("wss://relay.example.com", RelayOptions())
    await client.connect()
    
    # Subscribe with callback
    sub_id_identity = "agent-identity-monitor"
    filter_identity = Filter().kinds([Kind.CUSTOM_38100()]).limit(0)  # limit=0 for live only
    sub_out = await client.subscribe_with_id(sub_id_identity, filter_identity, handler)
    print(f"Subscription {sub_out.output} active, receiving via callback")
    
    # Multiple concurrent subscriptions
    sub_id_revocation = "agent-revocation-monitor"
    filter_revocation = Filter().kinds([Kind.CUSTOM_38101()]).limit(0)
    await client.subscribe_with_id(sub_id_revocation, filter_revocation, handler)
    
    # Keep running
    await asyncio.sleep(3600)
    
    # Cleanup
    client.unsubscribe(sub_id_identity)
    client.unsubscribe(sub_id_revocation)
    await client.disconnect()
```

## Pattern 2: async/await stream_events() (One-Shot)
Best for one-time event fetching with timeout.

```python
from nostr_sdk import Filter, Kind, Duration

async def fetch_identity_updates(client, agent_pubkey: str, timeout_secs: int = 10):
    """Fetch historical + recent identity events."""
    filter_obj = (Filter()
                  .kinds([Kind.CUSTOM_38100()])
                  .authors([agent_pubkey])
                  .limit(100))
    
    timeout = Duration.from_secs(timeout_secs)
    async with await client.stream_events([filter_obj], timeout) as stream:
        async for event in stream:
            print(f"Event ID: {event.id}, created_at: {event.created_at}")
```

## Pattern 3: Filter Construction for Your Use Cases

```python
from nostr_sdk import Filter, Kind

# 1. Identity rotations (Kind 38100) for specific d-tags
filter_identity = (Filter()
                   .kinds([Kind.CUSTOM_38100()])
                   .tags([("d", ["agent-id-1", "agent-id-2"])])  # multiple d-tags
                   .limit(0))  # live only, no history

# 2. Delegations revoked TO agent (Kind 38101, p-tag = agent pubkey)
filter_delegations = (Filter()
                      .kinds([Kind.CUSTOM_38101()])
                      .tags([("p", [agent_pubkey])])  # agent is delegatee
                      .limit(0))

# 3. New attestations where agent is attested (Kind 38102, p-tag = agent pubkey)
filter_attestations = (Filter()
                       .kinds([Kind.CUSTOM_38102()])
                       .tags([("p", [agent_pubkey])])
                       .limit(0))

# Combine filters for multi-kind subscription
filter_all = (Filter()
              .kinds([Kind.CUSTOM_38100(), Kind.CUSTOM_38101(), Kind.CUSTOM_38102()])
              .limit(0))
```

## Cancellation & Cleanup

```python
# Unsubscribe by ID
client.unsubscribe("subscription-id")

# Unsubscribe all active subscriptions
client.unsubscribe_all()

# View active subscriptions (dict[sub_id] -> dict[relay] -> [Filter])
active_subs = client.subscriptions()
for sub_id, relay_filters in active_subs.items():
    print(f"Subscription {sub_id}: {list(relay_filters.keys())}")

# Close client (disconnects all relays)
await client.disconnect()
```

## Reconnection & Long-Running Behavior

- **Auto-reconnect:** Client auto-reconnects on relay disconnect (Rust layer). No explicit retry logic needed.
- **Keep-alive:** Long-lived subscriptions via `subscribe()` remain active across relay hiccups.
- **Memory:** No inherent memory leak for long-running subscriptions; handler callbacks are fire-and-forget. If handler accumulates state (e.g., event logs), you must manage cleanup in your application code.

## Key Differences

| Feature | `stream_events()` | `subscribe() + callback` |
|---------|------------------|-------------------------|
| Lifetime | Auto-closing on EOSE/timeout | Long-lived (manual unsubscribe) |
| Memory overhead | Low (cleans up on EOSE) | Persistent until unsubscribe |
| Use case | Snapshot + recent updates | Real-time persistent monitoring |
| Multiple relays | Gossip-enabled (NIP65) | Broadcast to added relays |

## Notes

- **No threading:** All I/O is async/await. Never block with `time.sleep()` in handlers.
- **Event ordering:** No guarantee of strict FIFO across relays; events may arrive out-of-order or duplicated. Deduplicate by `event.id` if needed.
- **Limit=0:** Requests live events only (since subscription time). Use `limit(N)` for recent history before subscribing to live.
