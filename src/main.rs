mod packet;
mod parser;
mod types;

use packet::RawPacket;
use pcap::Device;

use crate::types::LinkType;

fn main() {
    let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
    let link_type = cap.get_datalink();

    loop {
        let packet = cap.next_packet().unwrap();
        let data = packet.data;

        let raw = RawPacket::new(data, Some(LinkType::from(link_type.0 as u16)));

        let ip_header = raw.get_ip_header().unwrap();
        // let tcp_header = raw.get_tcp_header().unwrap();

        println!("{:#?}", ip_header);
        // println!("{:#?}", tcp_header);
    }
}
