---
title: Roblox Browser Bridge
emoji: 🌐
colorFrom: blue
colorTo: gray
sdk: docker
app_port: 8080
pinned: false
---

# Roblox Browser Bridge

Headless Chromium streaming server for the Roblox browser client.

## Setup

1. In the Space's Settings > Variables and secrets, add a secret named `BRIDGE_KEY`
   with a long random value. Use the same value in the Roblox `BridgeKey` ModuleScript.
2. Wait for the build to finish, then open `https://YOUR-SPACE-URL/health`.
3. In Roblox, set `BridgeUrl` to `wss://YOUR-SPACE-URL/bridge`.

Your Space URL is `https://USERNAME-SPACENAME.hf.space`, and the WebSocket
address is `wss://USERNAME-SPACENAME.hf.space/bridge`.

## Blocked URLs

Edit `blockedHosts` in `server.js`. Loopback, private, and link-local addresses are always blocked.
