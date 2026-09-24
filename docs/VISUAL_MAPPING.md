# Visual mapping

Vehicles are visual metaphors, not protocol semantics. Each class has its own car model *and*
colour, so classes stay distinguishable for colour-blind users.

## Traffic class → vehicle

| Class (`TrafficClass`) | How it is assigned | Car model | Colour | Relative speed |
| --- | --- | --- | --- | --- |
| HTTPS / TLS | TLS record detected, TLS ports (443, 8443, 853, 993, 995, 465), or QUIC (UDP 443) | Coupe (sleek, glass canopy) | Cyan `#00d9ff` | 1.0 |
| HTTP | HTTP/1.x request/status line, or ports 80/8080 | Sedan | Blue `#3d7bff` | 1.0 |
| TCP | Any other TCP | Sedan | Violet `#9466ff` | 1.0 |
| UDP | Any other UDP | Compact hatch | Orange `#ff8a1f` | 1.1 |
| DNS | UDP/TCP 53, mDNS 5353, LLMNR 5355 | Motorbike (small, fast) | Green `#3dff8a` | 1.45 |
| ICMP | ICMPv4 / ICMPv6 | Interceptor (wedge, spoiler) | Red-pink `#ff3d7a` | 1.2 |
| ARP | ARP | Van (local-network service vehicle) | Yellow `#ffd23f` | 0.9 |
| DHCP | UDP 67/68, 546/547 | Van | Ice `#d8e1ff` | 0.85 |
| Other | Everything else | Compact hatch | Grey `#7d8aa8` | 1.0 |
| *Any, merged convoy* | ≥ 4 packets and ≥ 30 units long | Hauler: cab + neon-striped data container | Class colour | 1.0 |

Every car has paint in its class colour, a glass cabin, wheels with glowing rims, twin
headlights, a full-width taillight bar, side light strips and a class-coloured underglow; the
headlights and taillights also wash onto the wet road.

Application identity beats transport: a DNS query is a DNS dart, not a UDP compact. The view
filter keyword `tcp`/`udp`/`icmp` matches the *transport*, so `tcp` includes HTTPS and HTTP.

## Traffic properties → visual properties

| Data | Visual | Mapping |
| --- | --- | --- |
| Direction (My Traffic) | Carriageway | Incoming drives from the INTERNET gate toward **YOUR DEVICE**; outgoing drives away. Loopback drives outgoing. Transit is not on the personal highway ("off-map"). |
| Endpoints (Live Traffic) | Route | Source node → router interchange (roundabout) → destination node. Internet = highway to the gateway arch and globe, your device = beacon tower, LAN devices = facility towers on the LOCAL DEVICES avenue, broadcast/multicast = LAN BROADCAST plaza. Neighbouring devices turn at their shared junction. |
| Device traffic volume | Building height | log₁₀ of bytes sent + received |
| Flow | Lane | Hash of flow id picks a lane, so a conversation reads as one stream |
| Bytes | Length | 14 … 44 ground units, √(log-scale) over 60 B … 64 KiB |
| Bytes | Speed | Heavier vehicles up to 30 % slower |
| Packet rate | Speed | Busier network flows up to 60 % faster (log scale, saturates ~10k pkt/s) |
| Load beyond road capacity | Convoys | Waiting events of the same flow merge; the vehicle grows and the tooltip reads "Convoy of N packets" |
| Selection | White ring | Follows the selected vehicle, or circles the selected building |
| Followed connection | Emphasis | Vehicles of other flows dim to 16 % |
| Legend click | Visibility | Toggles a `!class:<name>` term in the view filter |
| Trip | Speed profile | Cars pull away at 35 % speed over 70 units, cruise, and brake over the last 90 units; they queue behind slower cars in their lane and steer smoothly through corners |

## Vehicle lifecycle

```
spawn (on-ramp gated by lane spacing) → fade in over first 24 units → accelerate → follow route → brake → arrive → fade out 0.35 s → slot freed
```
