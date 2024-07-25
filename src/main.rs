use std::{collections::HashMap, io};
use std::net::Ipv4Addr;

mod tcp;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),

}
fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();

    let mut nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let _flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_proto != 0x0800 {
            eprintln!("Ignoring non-IPv4 packet with proto {:x}", eth_proto);
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();
                let proto = ip_header.protocol();
                if proto != 0x06 {
                    eprintln!("Ignoring non-TCP packet with proto {:x}", proto);
                    continue;
                }
                let ip_header_size = ip_header.slice().len();
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + ip_header.slice().len()..nbytes])
                {
                    Ok(tcp_header) => {
                        let headers_size = 4 + ip_header_size + tcp_header.slice().len();
                        connections.entry(Quad {
                            src: (src, tcp_header.source_port()),
                            dst: (dst, tcp_header.destination_port()),
                        }).or_default().state.on_packet(&mut nic, ip_header, tcp_header, &buf[headers_size..nbytes])?;

                    }
                    Err(e) => {
                        eprintln!("Ignoring invalid TCP packet: {:?}", e);
                    }
                }

            }
            Err(e) => {
                eprintln!("Ignoring invalid IPv4 packet: {:?}", e);
            }
        }
    }
}
