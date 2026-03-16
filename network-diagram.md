# Network Diagram — IPv4→IPv6 Gateway für Invidious

```
Internet
    │
    │  IPv4-Browser
    │  yt.heissa.de → A 82.165.41.91
    ▼
┌─────────────────────────────────┐
│  VPS ipgate1 (82.165.41.91)     │
│  IONOS / 2a02:2479:8f:e700::1   │
│                                 │
│  socat-invidious.service        │
│  TCP4:7000 → TCP6:[OpenWrt]:7000│
│                                 │
│  WireGuard wg0 (10.9.0.1/24)   │
│  fwdsync.py DNAT chain          │
└──────────────┬──────────────────┘
               │ IPv6 (Exposed Host)
               │ 2a02:810d:4117:7300:1ad6:c7ff:fe90:bb17
               ▼
┌─────────────────────────────────┐
│  FritzBox                       │
│  WAN: 2a02:810d:4117:7300::/64  │
│  Delegiert /56 → OpenWrt        │
│  Exposed Host → OpenWrt         │
└──────────────┬──────────────────┘
               │ LAN 192.168.178.47
               ▼
┌─────────────────────────────────┐
│  OpenWrt (TP-Link)              │
│  eth0: 192.168.178.47           │
│  eth0: 2a02:810d:4117:7300::    │
│  br-lan: 192.168.5.1            │
│  br-lan: 2a02:810d:4117:73fd::1 │
│  wg0: 10.9.0.5                  │
│                                 │
│  DNAT: TCP6:7000                │
│    → 2a02:810d:4117:73fd::23    │
└──────────────┬──────────────────┘
               │ LAN 192.168.5.0/24
               │ IPv6 2a02:810d:4117:73fd::/64
               ▼
┌─────────────────────────────────┐
│  pve6 (Dell 64GB)               │
│  192.168.5.23                   │
│  2a02:810d:4117:73fd::23        │
│  pve6.heissa.de (AAAA only)     │
│                                 │
│  ┌─────────────────────────┐    │
│  │ Invidious  :7000        │    │
│  │ companion  :8282        │    │
│  │ TubeArchivist :8000     │    │
│  │ watch-cache   :9000     │    │
│  └─────────────────────────┘    │
│                                 │
│  gai.conf: IPv6-only            │
└──────────────┬──────────────────┘
               │ native IPv6
               ▼
         ┌───────────┐
         │  YouTube  │
         │ IPv6 only │
         └───────────┘

── IPv6-Browser ──────────────────────────────────
  yt.heissa.de → AAAA 2a02:810d:4117:73fd::23
  direkt → pve6 (FritzBox+OpenWrt transparent)
```
