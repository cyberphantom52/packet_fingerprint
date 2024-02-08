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
    /// Represents the version and IHL (Internet Header Length) field in a packet.
    /// - The version field is 4 bits long and represents the version of the IP protocol.
    /// - The IHL field is 4 bits long.
    /// 
    /// IHL is the number of 32-bit words in the header. The minimum value for this field is 5 (when no options are present),
    pub version_ihl: u8,

    /// Represents the Type of Service (ToS) field in a packet.
    /// - The first 6 bits represent the Differentiated Services Code Point (DSCP).
    /// - The last 2 bits represent the Explicit Congestion Notification (ECN).
    pub tos_ecn: u8,

    /// Represents the total length of the packet in bytes.
    pub total_length: u16,

    /// Represents the identification field in a packet.
    pub id: u16,

    /// Represents the flags and fragment offset fields in a packet.
    /// - The first 3 bits represent the flags.
    /// - The last 13 bits represent the fragment offset.
    pub flags_foffset: u16,
    pub time_to_live: u8,
    
    /// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    pub protocol: u8,
    pub checksum: u16,
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4],
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct IPV6Header {
    /// Represents the version, traffic class, and flow label fields in a packet.
    /// - The version field is 4 bits long and represents the version of the IP protocol.
    /// - The traffic class field is 8 bits long and represents the type of service.
    ///   - The first 6 bits represent the Differentiated Services Code Point (DSCP).
    ///   - The last 2 bits represent the Explicit Congestion Notification (ECN).
    /// - The flow label field is 20 bits long and represents the flow of the packet.
    pub ver_tos_ecn_flow: u32,
    
    /// Represents the payload length (means the length of the data in the packet, excluding the header) in bytes.
    pub payload_length: u16,
    pub next_header: u8,
    pub time_to_live: u8,
    pub source_ip: [u8; 16],
    pub destination_ip: [u8; 16],
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct EthernetHeader {
  destination: [u8; 6],
  source: [u8; 6],
  ether_type: u16,
}

impl std::fmt::Display for EthernetHeader {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      let destination = self.destination;
      let source = self.source;
      let ether_type = self.ether_type;
      
      write!(f, "Destination: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\nSource: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\nEtherType: {:04x}",
          destination[0], destination[1], destination[2], destination[3], destination[4], destination[5],
          source[0], source[1], source[2], source[3], source[4], source[5],
          ether_type
      )
  }
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