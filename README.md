# HaskShield

A Nostr-native shield that sits in front of a relay and keeps spam and floods out, without breaking any client.

Status: design stage. Nothing here is built yet. This file describes the plan.

## Why

Open relays are getting hit from two directions at once:

1. **Connection floods.** Huge numbers of IPs open websockets and hammer the relay with requests until it stops answering.
2. **Event spam.** Junk notes are written faster than any operator can clean them up.

Ordinary bot protection (browser challenges, captchas) does not work here. Nostr clients such as Damus, Primal and Amethyst cannot solve a browser challenge, so that kind of shield locks out real users together with the bots.

HaskShield only uses defences the Nostr protocol already supports, so every client keeps working unchanged.

## How it works

```
client (Damus, Primal, Amethyst, ...)
        |
        v
   HaskShield        <- decides who gets through
        |
        v
  relay (strfry or any other)
```

HaskShield is a websocket proxy. Clients connect to it exactly as they would to the relay. The relay behind it needs no changes.

Checks run cheapest first, so junk is rejected before it costs anything:

| Layer | What it checks | Cost |
|---|---|---|
| 1. Connection | Connections per IP, new connections per second, idle sockets | Very low |
| 2. Request | REQ rate per connection, number of open subscriptions, filter size | Low |
| 3. Event | Event size, rate per pubkey, duplicate content | Low |
| 4. Proof | Proof of work (NIP-13), auth (NIP-42) when the relay is under pressure | Medium |
| 5. Review | Optional slower check for unclear cases only | High |

Layers 4 and 5 switch on only when needed. In calm times the relay stays as open as its operator wants.

## Planned features

- Per-IP connection and rate limits
- Per-pubkey write limits
- Pressure mode: raise proof-of-work or require auth automatically while under attack, relax afterwards
- Allow list and block list (pubkeys, IPs)
- One config file, sensible defaults
- Runs as a single container next to the relay
- Plain counters for what was let through and what was rejected, and why

## What it will not do

- It cannot absorb a very large volumetric attack on a small server. It makes rejecting junk cheap, which keeps the relay up far longer, but bandwidth is still bandwidth.
- It does not read or judge the meaning of ordinary posts. It limits behaviour, not opinions.
- It does not need, or ask for, any change in Nostr clients.

## Open decisions

- Language: Rust or Node
- Proxy only, or also a strfry write-policy plugin for layer 3
- How pressure mode decides that the relay is under attack
- Licence

## Test bed

The first deployment target is the open relay at `wss://hasky.chat`.

## Made by

Hasky Labs, Copenhagen.
