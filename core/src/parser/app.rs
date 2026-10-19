//! Application protocol identification. Port numbers are only *hints*; payload signatures
//! (TLS record, HTTP request line, DNS header) take precedence when present.

use super::{dhcp, dns, http, netbios, tls};
use crate::packet::{AppProtocol, ParsedPacket, TransportProtocol};

const DNS_TCP_LENGTH_PREFIX: usize = 2;

pub(super) fn detect(payload: &[u8], pkt: &mut ParsedPacket) {
    let (Some(sp), Some(dp)) = (pkt.src_port(), pkt.dst_port()) else {
        return;
    };
    let port_hint = |set: &[u16]| set.contains(&sp) || set.contains(&dp);

    match pkt.transport {
        TransportProtocol::Udp => {
            pkt.app = udp_hint(&port_hint);
            match pkt.app {
                AppProtocol::Dns | AppProtocol::Mdns | AppProtocol::Llmnr => pkt.dns = dns::parse(payload, pkt),
                AppProtocol::Dhcp => pkt.dhcp = dhcp::parse(payload),
                AppProtocol::Nbns => pkt.netbios = netbios::parse(payload),
                _ => {}
            }
        }
        TransportProtocol::Tcp => {
            if let Some(info) = tls::parse(payload) {
                pkt.app = AppProtocol::Tls;
                pkt.tls = Some(info);
            } else if let Some(info) = http::parse(payload) {
                pkt.app = AppProtocol::Http;
                pkt.http = Some(info);
            } else if payload.starts_with(b"SSH-") || port_hint(&[22]) {
                pkt.app = AppProtocol::Ssh;
            } else if port_hint(&[53]) {
                pkt.app = AppProtocol::Dns;
                if payload.len() > DNS_TCP_LENGTH_PREFIX {
                    pkt.dns = dns::parse(&payload[DNS_TCP_LENGTH_PREFIX..], pkt);
                }
            } else if port_hint(&[443, 8443, 853, 993, 995, 465]) {
                pkt.app = AppProtocol::Tls;
            } else if port_hint(&[80, 8080]) {
                pkt.app = AppProtocol::Http;
            }
        }
        _ => {}
    }
}

fn udp_hint(port_hint: &impl Fn(&[u16]) -> bool) -> AppProtocol {
    if port_hint(&[53]) {
        AppProtocol::Dns
    } else if port_hint(&[5353]) {
        AppProtocol::Mdns
    } else if port_hint(&[5355]) {
        AppProtocol::Llmnr
    } else if port_hint(&[67, 68]) {
        AppProtocol::Dhcp
    } else if port_hint(&[546, 547]) {
        AppProtocol::Dhcpv6
    } else if port_hint(&[123]) {
        AppProtocol::Ntp
    } else if port_hint(&[1900]) {
        AppProtocol::Ssdp
    } else if port_hint(&[137]) {
        AppProtocol::Nbns
    } else if port_hint(&[443]) {
        AppProtocol::Quic
    } else {
        AppProtocol::Unknown
    }
}
