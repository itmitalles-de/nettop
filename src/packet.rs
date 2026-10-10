//! Header-only parsing. The capture worker never retains packet payloads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum Protocol {
    Tcp,
    Udp,
    Other(u8),
}

impl Protocol {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Other(_) => "IP",
        }
    }

    fn from_number(value: u8) -> Self {
        match value {
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Other(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum Direction {
    Incoming,
    Outgoing,
    Unknown,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct Flow {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Protocol,
    pub interface_index: u32,
    pub direction: Direction,
}

/// Identifies the fragments of one IP datagram. Only the first fragment carries
/// transport ports; later fragments borrow them through a short-lived cache.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct FragmentKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub id: u32,
    pub protocol: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Fragment {
    /// Offset zero with more fragments following; ports are present.
    First(FragmentKey),
    /// A nonzero offset; transport ports are not part of this packet.
    Later(FragmentKey),
}

#[derive(Clone, Debug)]
pub(super) struct Packet {
    pub flow: Flow,
    pub bytes: u64,
    pub fragment: Option<Fragment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParseError {
    Unsupported,
    Truncated,
    Invalid,
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, ParseError> {
    let bytes = data.get(offset..offset + 2).ok_or(ParseError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn direction(packet_type: u16) -> Direction {
    match packet_type {
        4 => Direction::Outgoing,
        0..=3 => Direction::Incoming,
        _ => Direction::Unknown,
    }
}

pub(super) fn parse(data: &[u8], wire_length: u32, datalink: i32) -> Result<Packet, ParseError> {
    let (mut offset, mut ethertype, interface_index, direction) = match datalink {
        // Linux cooked v2 includes the actual interface index, unlike SLL1.
        276 => {
            let header = data.get(..20).ok_or(ParseError::Truncated)?;
            let interface_index = u32::from_be_bytes(header[4..8].try_into().unwrap());
            (
                20,
                u16_at(header, 0)?,
                interface_index,
                direction(header[10] as u16),
            )
        }
        113 => {
            let header = data.get(..16).ok_or(ParseError::Truncated)?;
            (16, u16_at(header, 14)?, 0, direction(u16_at(header, 0)?))
        }
        1 => {
            data.get(..14).ok_or(ParseError::Truncated)?;
            (14, u16_at(data, 12)?, 0, Direction::Unknown)
        }
        12 | 101 => {
            let version = data.first().ok_or(ParseError::Truncated)? >> 4;
            let ethertype = match version {
                4 => 0x0800,
                6 => 0x86dd,
                _ => return Err(ParseError::Unsupported),
            };
            (0, ethertype, 0, Direction::Unknown)
        }
        _ => return Err(ParseError::Unsupported),
    };
    // Handle nested 802.1Q and 802.1ad tags with a finite header walk.
    for _ in 0..4 {
        if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        ethertype = u16_at(data, offset + 2)?;
        offset += 4;
    }
    let ip = data.get(offset..).ok_or(ParseError::Truncated)?;
    // (first fragment, identification, protocol of the fragmented payload)
    let mut fragment: Option<(bool, u32, u8)> = None;
    let (source, destination, protocol, transport_offset, ports_present, bytes) = match ethertype {
        0x0800 => {
            let header = ip.get(..20).ok_or(ParseError::Truncated)?;
            if header[0] >> 4 != 4 {
                return Err(ParseError::Invalid);
            }
            let header_length = (header[0] & 15) as usize * 4;
            if header_length < 20 {
                return Err(ParseError::Invalid);
            }
            ip.get(..header_length).ok_or(ParseError::Truncated)?;
            let total_length = u16_at(header, 2)? as usize;
            let available = wire_length.saturating_sub(offset as u32) as usize;
            // Linux BIG TCP/GSO exposes IPv4 super-packets above 64 KiB with a
            // zero total length, like IPv6 jumbo frames with payload length 0.
            let length = if total_length == 0 && available > 65_535 {
                available
            } else {
                total_length
            };
            if length < header_length || length > available {
                return Err(ParseError::Invalid);
            }
            let source = IpAddr::V4(Ipv4Addr::new(
                header[12], header[13], header[14], header[15],
            ));
            let destination = IpAddr::V4(Ipv4Addr::new(
                header[16], header[17], header[18], header[19],
            ));
            let flags_offset = u16_at(header, 6)?;
            let first_fragment = flags_offset & 0x1fff == 0;
            if !first_fragment || flags_offset & 0x2000 != 0 {
                fragment = Some((first_fragment, u32::from(u16_at(header, 4)?), header[9]));
            }
            (
                source,
                destination,
                header[9],
                header_length,
                first_fragment,
                length as u64,
            )
        }
        0x86dd => {
            let header = ip.get(..40).ok_or(ParseError::Truncated)?;
            if header[0] >> 4 != 6 {
                return Err(ParseError::Invalid);
            }
            let payload_length = u16_at(header, 4)? as u64;
            // Linux may expose large, offloaded frames before segmentation.
            let length = if payload_length == 0 {
                wire_length.saturating_sub(offset as u32) as u64
            } else {
                payload_length + 40
            };
            if length < 40 || length > wire_length.saturating_sub(offset as u32) as u64 {
                return Err(ParseError::Invalid);
            }
            let source = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&header[8..24]).unwrap(),
            ));
            let destination = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&header[24..40]).unwrap(),
            ));
            let mut protocol = header[6];
            let mut cursor = 40;
            let mut first_fragment = true;
            for _ in 0..8 {
                let extension_length = match protocol {
                    0 | 43 | 60 => {
                        (*ip.get(cursor + 1).ok_or(ParseError::Truncated)? as usize + 1) * 8
                    }
                    51 => (*ip.get(cursor + 1).ok_or(ParseError::Truncated)? as usize + 2) * 4,
                    44 => {
                        let offset_flags = u16_at(ip, cursor + 2)?;
                        first_fragment = offset_flags & 0xfff8 == 0;
                        let id = ip
                            .get(cursor + 4..cursor + 8)
                            .ok_or(ParseError::Truncated)?;
                        // Atomic fragments (offset 0, no M flag) need no cache.
                        if !first_fragment || offset_flags & 1 != 0 {
                            fragment = Some((
                                first_fragment,
                                u32::from_be_bytes(id.try_into().unwrap()),
                                ip[cursor],
                            ));
                        }
                        8
                    }
                    _ => break,
                };
                ip.get(cursor..cursor + extension_length)
                    .ok_or(ParseError::Truncated)?;
                protocol = ip[cursor];
                cursor += extension_length;
                if !first_fragment {
                    break;
                }
            }
            (
                source,
                destination,
                protocol,
                cursor,
                first_fragment,
                length,
            )
        }
        _ => return Err(ParseError::Unsupported),
    };
    let protocol = Protocol::from_number(protocol);
    let (source_port, destination_port) =
        if ports_present && matches!(protocol, Protocol::Tcp | Protocol::Udp) {
            // Only the first four transport bytes are needed; no payload is copied.
            if transport_offset + 4 > bytes as usize {
                return Err(ParseError::Invalid);
            }
            (
                Some(u16_at(ip, transport_offset)?),
                Some(u16_at(ip, transport_offset + 2)?),
            )
        } else {
            (None, None)
        };
    let fragment = fragment.and_then(|(first, id, fragment_protocol)| {
        let key = FragmentKey {
            source,
            destination,
            id,
            protocol: fragment_protocol,
        };
        if !first {
            Some(Fragment::Later(key))
        } else {
            source_port.map(|_| Fragment::First(key))
        }
    });
    Ok(Packet {
        flow: Flow {
            source,
            destination,
            source_port,
            destination_port,
            protocol,
            interface_index,
            direction,
        },
        bytes,
        fragment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(protocol: u8) -> Vec<u8> {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&12345_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet
    }

    #[test]
    fn sll2_preserves_interface_direction_and_ip_byte_count() {
        let mut data = vec![0; 20];
        data[..2].copy_from_slice(&0x0800_u16.to_be_bytes());
        data[4..8].copy_from_slice(&42_u32.to_be_bytes());
        data[10] = 4;
        data.extend(ipv4(6));
        let parsed = parse(&data, 48, 276).unwrap();
        assert_eq!(parsed.flow.interface_index, 42);
        assert_eq!(parsed.flow.direction, Direction::Outgoing);
        assert_eq!(parsed.flow.source_port, Some(12345));
        assert_eq!(parsed.bytes, 28);
    }

    #[test]
    fn noninitial_fragment_keeps_bytes_without_inventing_ports() {
        let mut data = ipv4(17);
        data[6..8].copy_from_slice(&1_u16.to_be_bytes());
        data[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        let parsed = parse(&data, 28, 101).unwrap();
        assert_eq!(parsed.flow.source_port, None);
        assert_eq!(parsed.flow.protocol, Protocol::Udp);
        assert_eq!(parsed.bytes, 28);
        let later = FragmentKey {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            id: 0x1234,
            protocol: 17,
        };
        assert_eq!(parsed.fragment, Some(Fragment::Later(later)));
        // The first fragment (offset 0, MF set) carries the ports to remember.
        data[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        let first = parse(&data, 28, 101).unwrap();
        assert_eq!(first.flow.destination_port, Some(443));
        assert_eq!(first.fragment, Some(Fragment::First(later)));
        // Unfragmented datagrams carry no fragment state.
        data[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        assert_eq!(parse(&data, 28, 101).unwrap().fragment, None);
    }

    #[test]
    fn ipv6_fragments_expose_identification() {
        let mut data = vec![0; 56];
        data[0] = 0x60;
        data[4..6].copy_from_slice(&16_u16.to_be_bytes());
        data[6] = 44;
        data[23] = 1;
        data[39] = 2;
        data[40] = 17;
        data[42..44].copy_from_slice(&1_u16.to_be_bytes()); // offset 0, M flag
        data[44..48].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
        data[48..50].copy_from_slice(&123_u16.to_be_bytes());
        data[50..52].copy_from_slice(&456_u16.to_be_bytes());
        let first = parse(&data, 56, 101).unwrap();
        assert_eq!(first.flow.source_port, Some(123));
        let Some(Fragment::First(key)) = first.fragment else {
            panic!("first fragment not recognized: {:?}", first.fragment);
        };
        assert_eq!((key.id, key.protocol), (0xdead_beef, 17));
        data[42..44].copy_from_slice(&(8_u16 << 3).to_be_bytes());
        let later = parse(&data, 56, 101).unwrap();
        assert_eq!(later.flow.source_port, None);
        assert_eq!(later.flow.protocol, Protocol::Udp);
        assert_eq!(later.fragment, Some(Fragment::Later(key)));
    }

    #[test]
    fn ipv4_big_tcp_uses_wire_length_for_zero_total_length() {
        let mut data = ipv4(6);
        data[2..4].copy_from_slice(&0_u16.to_be_bytes());
        let parsed = parse(&data, 100_000, 101).unwrap();
        assert_eq!(parsed.bytes, 100_000);
        assert_eq!(parsed.flow.destination_port, Some(443));
        // A zero length below the 64 KiB limit remains malformed.
        assert_eq!(parse(&data, 60_000, 101).unwrap_err(), ParseError::Invalid);
    }

    #[test]
    fn ipv6_extension_headers_and_udp_are_parsed() {
        let mut data = vec![0; 56];
        data[0] = 0x60;
        data[4..6].copy_from_slice(&16_u16.to_be_bytes());
        data[6] = 0;
        data[23] = 1;
        data[39] = 2;
        data[40] = 17;
        data[48..50].copy_from_slice(&123_u16.to_be_bytes());
        data[50..52].copy_from_slice(&456_u16.to_be_bytes());
        let parsed = parse(&data, 56, 101).unwrap();
        assert_eq!(parsed.flow.protocol, Protocol::Udp);
        assert_eq!(parsed.flow.destination_port, Some(456));
        assert_eq!(parsed.bytes, 56);
    }

    #[test]
    fn vlan_and_truncation_are_explicit() {
        let mut data = vec![0; 18];
        data[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        data[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
        data.extend(ipv4(17));
        assert_eq!(
            parse(&data, 46, 1).unwrap().flow.destination_port,
            Some(443)
        );
        assert_eq!(
            parse(&data[..30], 46, 1).unwrap_err(),
            ParseError::Truncated
        );
    }

    #[test]
    fn every_short_capture_is_safe() {
        for datalink in [1, 12, 101, 113, 276, 999] {
            for length in 0..192 {
                let data = vec![0xff; length];
                let _ = parse(&data, length as u32, datalink);
            }
        }
    }
}
