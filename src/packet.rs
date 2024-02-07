use crate::types::*;

pub struct RawPacket<'a> {
    data: &'a [u8],
    pub offset: Option<usize>,
}

impl<'a> RawPacket<'a> {
    pub fn new(data: &'a [u8], link_type: Option<LinkType>) -> RawPacket<'a> {
        let mut result = RawPacket { data, offset: None };
        result.calculate_offset(link_type).unwrap();
        result
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
        self.offset.unwrap_or(0)
    }

    pub fn calculate_offset(&mut self, link_type: Option<LinkType>) -> Result<(), String> {
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
            return Ok(());
        }

        loop {
            let data = &self.data[self.get_offset()..];

            if data.len() < MIN_TCP4 {
                return Err("Packet too short".to_string());
            }

            if self.get_offset() >= IPV6_HDR_LEN {
                return Err("No IP packet found".to_string());
            }

            let ip_version = self.ip_version();

            let is_valid = match ip_version {
                Ok(IpAddr::V4) => {
                    data[9] == 6
                },
                Ok(IpAddr::V6) => {
                    if data.len() >= MIN_TCP6 {
                        data[6] == 6
                    } else {
                        false
                    }
                }
                Err(_) => {
                    false
                },
            };

            if is_valid {
                return Ok(());
            }

            self.offset = Some(self.get_offset() + 2);
        }
    }
}
