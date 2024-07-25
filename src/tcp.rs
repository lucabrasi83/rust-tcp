use std::io;

#[derive(Debug)]
pub enum TcpState {
    Closed,
    Listen,
    SynRecvd,
    Established,
}

pub struct Connection {
    pub state: TcpState,
    pub send: SendSequenceSpace,
    pub rcvd: ReceiveSequenceSpace,
}

struct SendSequenceSpace {
    /// send next
    nxt: usize,
    /// send unacknowledged
    una: usize,
    /// send window
    wnd: usize,
    /// send urgent pointer
    up: bool,
}

struct ReceiveSequenceSpace {
    /// send next
    nxt: usize,
    /// send unacknowledged
    una: usize,
    /// send window
    wnd: usize,
    /// initial receive sequence number
    irs: usize,
}

impl Default for Connection {
    fn default() -> Self {
        // TcpState::Closed
        Connection {
            state: TcpState::Listen,
        }
    }
}

impl TcpState {
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];

        match *self {
            TcpState::Closed => {
                return Ok(0);
            }
            TcpState::Listen => {
                if !tcp_header.syn() {
                    eprintln!("Expected SYN packet, got {:?}", tcp_header);
                    return Ok(0);
                }
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    0,
                    500,
                );
                syn_ack.syn = true;
                syn_ack.ack = true;
                syn_ack.acknowledgment_number = tcp_header.sequence_number().wrapping_add(1);
                let ip = etherparse::Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    etherparse::IpTrafficClass::Tcp,
                    ip_header.destination_addr().octets(),
                    ip_header.source_addr().octets(),
                );
                // write out the headers
                let unwritten = {
                    let mut unwritten = &mut buf[..];

                    ip.write(&mut unwritten);
                    syn_ack.write(&mut unwritten);
                    unwritten.len()
                };

                nic.send(&buf[..unwritten])?;
            }
            TcpState::SynRecvd => {
                if tcp_header.syn() && tcp_header.ack() {
                    eprintln!("Got SYN+ACK, transitioning to Established");
                    return Ok(0);
                }
            }
            TcpState::Established => {
                if tcp_header.fin() {
                    eprintln!("Got FIN, transitioning to Closed");
                    return Ok(0);
                }
            }
        }
        eprintln!(
            "{}:{} -> {}:{}  {} bytes of TCP",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len()
        );
        Ok(0)
    }
}
