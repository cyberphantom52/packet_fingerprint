use crate::types::*;

pub struct RawPacket<'a> {
    data: &'a [u8],
    pub offset: Option<usize>,
}

impl<'a> RawPacket<'a> {
    pub fn new(data: &'a [u8], link_type: Option<LinkType>) -> RawPacket<'a> {
        let mut result = RawPacket { data, offset: None };
        result.calculate_offset(link_type);
        result
    }

    pub fn get_ethernet_header(&self) -> Result<EthernetHeader, String> {
        if self.get_offset() < 14 {
            return Err("Packet too short".to_string());
        }

        let raw = &self.data[..14];
        let eth = unsafe { *(raw.as_ptr() as *const EthernetHeader) };

        Ok(eth)
    }

    pub fn get_ip_header(&self) -> Result<IpHeader, String> {
        let raw = &self.data[self.get_offset()..];
        match self.ip_version() {
            Ok(IpAddr::V4) => {
                if raw.len() < MIN_TCP4 {
                    return Err("Packet too short".to_string());
                }
                let ip = unsafe { *(raw.as_ptr() as *const IPV4Header) };
                return Ok(IpHeader::V4(ip));
            }
            Ok(IpAddr::V6) => {
                if raw.len() < MIN_TCP6 {
                    return Err("Packet too short".to_string());
                }
                let ip = unsafe { *(raw.as_ptr() as *const IPV6Header) };
                return Ok(IpHeader::V6(ip));
            }
            Err(e) => return Err(e),
        }
    }

    pub fn get_tcp_header(&self) -> Result<TCPHeader, String> {
        let ip_version = self.ip_version()?;
        let offset = self.get_offset()
            + match ip_version {
                IpAddr::V4 => IPV4_HDR_LEN,
                IpAddr::V6 => IPV6_HDR_LEN,
            };
        let raw = &self.data[offset..];

        if raw.len() < TCP_HDR_LEN {
            return Err("Packet too short".to_string());
        }

        let tcp = unsafe { *(raw.as_ptr() as *const TCPHeader) };

        Ok(tcp)
    }

    pub fn ip_version(&self) -> Result<IpAddr, String> {
        let ver = self.data[self.get_offset()] >> 4;
        match ver {
            4 => Ok(IpAddr::V4),
            6 => Ok(IpAddr::V6),
            _ => Err("Unknown IP version".to_string()),
        }
    }

    pub fn get_offset(&self) -> usize {
        // default to ethernet header length
        self.offset.unwrap_or(14)
    }

    fn calculate_offset(&mut self, link_type: Option<LinkType>) {
        self.offset = match link_type {
            Some(LinkType::Raw) => Some(0),
            Some(LinkType::Null) | Some(LinkType::Ppp) => Some(4),
            Some(LinkType::Loop) | Some(LinkType::PppHdlc) | Some(LinkType::PppEther) => {
                Some(8)
            }
            Some(LinkType::Ethernet) => Some(14),
            Some(LinkType::LinuxSll) => Some(16),
            Some(LinkType::LinuxSll2) => Some(20),
            Some(LinkType::Pflog) => Some(28),
            Some(LinkType::Ieee802_11) => Some(32),
            _ => None,
        };

        if self.offset.is_some() {
            return;
        }

        for offset in (0..IPV6_HDR_LEN).step_by(2) {
            let data = &self.data[offset..];

            if data.len() < MIN_TCP4 {
                return;
            }

            let ip_version = match data[0] >> 4 {
                4 => IpAddr::V4,
                6 => {
                    if data.len() >= MIN_TCP6 {
                        IpAddr::V6
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            let protocol = match ip_version {
                IpAddr::V4 => data[9],
                IpAddr::V6 => data[6],
            };

            // TCP or UDP
            if protocol == 6 {
                self.offset = Some(offset);
                return;
            }
        }
    }
}
