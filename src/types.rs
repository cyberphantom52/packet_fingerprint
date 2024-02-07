use std::mem::size_of;

pub const MIN_TCP4: usize = size_of::<IPV4Header>() + size_of::<TCPHeader>();
pub const MIN_TCP6: usize = size_of::<IPV6Header>() + size_of::<TCPHeader>();

pub const IPV4_HDR_LEN: usize = size_of::<IPV4Header>();
pub const IPV6_HDR_LEN: usize = size_of::<IPV6Header>();
pub const TCP_HDR_LEN: usize = size_of::<TCPHeader>();

pub enum IpAddr {
  V4,
  V6,
}

#[derive(Debug)]
pub enum IpHeader {
  V4(IPV4Header),
  V6(IPV6Header),
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct IPV4Header {
    pub ver_hlen: u8,   // IP version (4), IP hdr len in dwords (4)
    pub tos_ecn: u8,    // ToS field (6), ECN flags (2)
    pub tot_len: u16,   // Total packet length, in bytes
    pub id: u16,        // IP ID
    pub flags_off: u16, // Flags (3), fragment offset (13)
    pub ttl: u8,        // Time to live
    pub proto: u8,      // Next protocol
    pub cksum: u16,     // Header checksum
    pub src: [u8; 4],   // Source IP
    pub dst: [u8; 4],   // Destination IP
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct IPV6Header {
    pub ver_tos: u32,  // Version (4), ToS (6), ECN (2), flow (20)
    pub pay_len: u16,  // Total payload length, in bytes
    pub proto: u8,     // Next protocol
    pub ttl: u8,       // Time to live
    pub src: [u8; 16], // Source IP
    pub dst: [u8; 16], // Destination IP
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct TCPHeader {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    /// 4 MSBs data offset and rest 4 bits reserved
    data_offset_reserved: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

pub enum LinkType {
  /// https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
  Null,
  Ethernet,
  Ppp = 9,
  PppHdlc = 50,
  PppEther,
  Raw = 101,
  Ieee802_11 = 105,
  /// https://www.tcpdump.org/linktypes/LINKTYPE_LOOP.html
  Loop = 108,
  /// https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
  LinuxSll = 113,
  Pflog = 117,
  /// https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
  LinuxSll2 = 276,
}

impl From<u16> for LinkType {
  fn from(value: u16) -> Self {
      match value {
          0 => LinkType::Null,
          1 => LinkType::Ethernet,
          9 => LinkType::Ppp,
          50 => LinkType::PppHdlc,
          51 => LinkType::PppEther,
          101 => LinkType::Raw,
          105 => LinkType::Ieee802_11,
          108 => LinkType::Loop,
          113 => LinkType::LinuxSll,
          117 => LinkType::Pflog,
          276 => LinkType::LinuxSll2,
          _ => LinkType::Null,
      }
  }
}