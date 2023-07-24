use pnet::{
    packet::{icmp::IcmpTypes, *},
    transport::*,
};
use std::{error::Error, fmt, mem, net::IpAddr, process, time, vec};

pub trait PrettyUnwrap<T, E> {
    fn pretty_unwrap(self, msg: Option<&str>) -> T;
}
impl<T, E> PrettyUnwrap<T, E> for Result<T, E>
where
    E: Error,
{
    fn pretty_unwrap(self, msg: Option<&str>) -> T {
        match self {
            Ok(val) => val,
            Err(err) => {
                // Handle the error
                if let Some(msg) = msg {
                    eprintln!("\x1b[31m{}: {}\x1b[m", msg, err);
                    process::exit(1);
                } else {
                    eprintln!("\x1b[31m{}\x1b[m", err);
                    process::exit(1);
                }
            }
        }
    }
}

const DEFAULT_TTL: u8 = 64;
// Reference: https://github.com/Daniel-Liu-c0deb0t/9S

pub struct Pinger {
    t_addr: IpAddr,

    payload_size: usize,

    total_pings: usize,
    lost_packets: usize,
    rtt_total: u128,
    avg_rtt_ns: u128,
    avg_rtt: time::Duration,

    tx: TransportSender,
    rx: TransportReceiver,

    timeout: time::Duration,

    id: u16,
    icmp_seq: u16,
}

pub struct EchoResponse {
    // send_time: time::Instant,
    rtt: time::Duration,
    id: u16,
    icmp_seq: u16,
    s_addr: IpAddr,
    size: usize,
}

impl EchoResponse {
    pub fn rtt(&self) -> time::Duration{
        self.rtt
    }
    pub fn id(&self) -> u16{
        self.id
    }
    pub fn icmp_seq(&self) -> u16{
        self.icmp_seq
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn s_addr(&self) -> IpAddr{
        self.s_addr
    }
}

#[derive(Debug)]
struct SimpleError {
    details: String,
}

impl SimpleError {
    fn new(msg: &str) -> SimpleError {
        SimpleError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for SimpleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for SimpleError {
    fn description(&self) -> &str {
        &self.details
    }
}

impl Pinger {
    pub fn new(addr: IpAddr, timeout: time::Duration, payload_size: usize) -> Pinger {
        let (tx, rx) = match addr {
            IpAddr::V4(_) => {
                // Ipv4 doesnt support ttl?
                let (mut tx, rx) = transport_channel(
                    1024,
                    TransportChannelType::Layer4(TransportProtocol::Ipv4(
                        ip::IpNextHeaderProtocols::Icmp,
                    )),
                )
                .pretty_unwrap(Some("Failed to open transport channel"));
                tx.set_ttl(DEFAULT_TTL)
                    .pretty_unwrap(Some("Failed to set ttl for tx"));
                (tx, rx)
            }
            IpAddr::V6(_) => transport_channel(
                1024,
                TransportChannelType::Layer4(TransportProtocol::Ipv6(
                    ip::IpNextHeaderProtocols::Icmpv6,
                )),
            )
            .pretty_unwrap(Some("Failed to open transport channel")),
        };
        Pinger {
            t_addr: addr,
            payload_size: payload_size,
            total_pings: 0,
            lost_packets: 0,
            rtt_total: 0,
            avg_rtt: time::Duration::new(0, 0),
            avg_rtt_ns: 0,
            tx: tx,
            rx: rx,
            id: process::id() as u16,
            icmp_seq: 0,
            timeout: timeout,
        }
    }
    /*fn make_icmpv6_packet(
        dest: IpAddr,
        icmp_buffer: &mut [u8],
        identifier: u16,
        icmp_seq: u16,
    ) -> icmpv6::Icmpv6Packet {
        match dest {
            IpAddr::V6(dest) => {
                let mut icmp_packet = icmpv6::MutableIcmpv6Packet::new(icmp_buffer).unwrap();
                icmp_packet.populate(&icmpv6::Icmpv6 {
                    icmpv6_type: icmpv6::Icmpv6Types::EchoRequest,
                    icmpv6_code: icmpv6::Icmpv6Code::new(0),
                    checksum: 0,
                    payload: Pinger::mk_payload(identifier, icmp_seq),
                });

                // this checksum calculation requires the source IPv6 address, which we don't immediately have
                // therefore, we just set it as all zeros; however this may lead to problems with checksum validation
                icmp_packet.set_checksum(icmpv6::checksum(
                    &icmp_packet.to_immutable(),
                    &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                    &dest,
                ));
                icmp_packet.consume_to_immutable()
            }
            _ => {
                panic!("W-ww--w What?")
            }
        }
    }*/

    // There should be a way to work around the borrow checker so i dont need to consume self
    pub fn ping_throw(&mut self) -> Result<EchoResponse, Box<dyn Error>> {
        let mut buf = vec![0u8; self.payload_size];
        let bsend_time = time::Instant::now();
        match self.t_addr {
            IpAddr::V4(_) => {
                let packet = make_icmp_packet(&mut buf, self.id, self.icmp_seq);
                self.tx
                    .send_to(packet, self.t_addr)
                    .pretty_unwrap(Some("Failed to tx.send_to"));
                match self.v4_recv(bsend_time) {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            IpAddr::V6(_) => {
                /*let packet =
                    Pinger::make_icmpv6_packet(self.t_addr, &mut buf, self.id, self.icmp_seq);
                self.tx
                    .send_to(packet, self.t_addr)
                    .pretty_unwrap(Some("Failed to tx.send_to ipv6"));
                Pinger::v4_recv_thread(self.rx);*/
                panic!("Ipv6 not supported yet")
            }
        }
    }

    /*fn calc_avg_rtt(&mut self, t: u128) {
        self.avg_rtt_ns = (self.avg_rtt_ns + t) / (self.total_pings as u128);
        self.avg_rtt = time::Duration::from_nanos(self.avg_rtt_ns as u64)
    }*/

    fn v4_recv(&mut self,bsend: time::Instant) -> Result<EchoResponse, Box<dyn Error>> {
        let mut tr = icmp_packet_iter(&mut self.rx);
        let (resp_packet, resp_ip) = match tr.next_with_timeout(self.timeout) {
            Ok(t) => match t {
                Some(s) => s,
                None => {
                    return Err(Box::new(SimpleError::new(
                        "No data",
                    )));
                }
            },
            Err(e) => {
                return Err(Box::new(SimpleError::new(
                    format!("tr.next() err: {e}").as_str(),
                )));
            }
        };
        let now = time::Instant::now();
        let payload = read_payload(&resp_packet.payload(), resp_ip,bsend);
        self.total_pings += 1;
        self.rtt_total += now.duration_since(bsend).as_nanos();
        self.avg_rtt_ns = self.rtt_total  / (self.total_pings as u128);
        self.avg_rtt = time::Duration::from_nanos(self.avg_rtt_ns as u64);
        match resp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                if payload.id != self.id {
                    return Err(Box::new(SimpleError::new("Duh what??")));
                }
                self.icmp_seq += 1;
                return Ok(payload);
            }
            IcmpTypes::DestinationUnreachable => {
                self.lost_packets += 1;
                return Err(Box::new(SimpleError::new(
                    format!("{}: destination Unreachable", self.t_addr).as_str(),
                )));
            }
            _ => {
                self.lost_packets += 1;
                return Err(Box::new(SimpleError::new(
                    format!(
                        "Invalid ICMP Echo reply type: {:?}",
                        resp_packet.get_icmp_type()
                    )
                    .as_str(),
                )));
            }
        };
    }

    pub fn total_pings(&self) -> usize {
        self.total_pings
    }

    pub fn lost_packets(&self) -> usize {
        self.lost_packets
    }

    pub fn t_addr(&self) -> IpAddr{
        self.t_addr
    }

    pub fn avg_rtt(&self) -> time::Duration {
        self.avg_rtt
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn icmp_seq(&self) -> u16{
        self.icmp_seq
    }
}

fn read_payload(payload: &[u8], ip: IpAddr, bsend: time::Instant) -> EchoResponse {
    /*let send_time = unsafe {
        let num = 0u128;
        let mut arr = mem::transmute::<u128, [u8; 16]>(num);
        arr.copy_from_slice(&payload[4..20]);
        mem::transmute::<[u8; 16], u128>(arr)
    };*/
    // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
    let id = payload[0] as u16 + ((payload[1] as u16) << 8); // identifier
    let icmp_seq = payload[2] as u16 + ((payload[3] as u16) << 8);
    let now = time::Instant::now();
    EchoResponse {
        // send_time: time::Inst,
        rtt: now.duration_since(bsend),
        id: id,
        icmp_seq: icmp_seq,
        s_addr: ip,
        size: payload.len()
    }
}

fn mk_payload(id: u16, icmp_seq: u16) -> Vec<u8> {
    let now = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let arr = unsafe { mem::transmute::<u128, [u8; 16]>(now) };
    let mut res = vec![
        (id & ((1 << 8) - 1)) as u8,
        (id >> 8) as u8,
        (icmp_seq & ((1 << 8) - 1)) as u8,
        (icmp_seq >> 8) as u8,
    ];
    res.extend_from_slice(&arr);
    res
}

fn make_icmp_packet(icmp_buffer: &mut [u8], id: u16, icmp_seq: u16) -> icmp::IcmpPacket {
    let mut icmp_packet = icmp::MutableIcmpPacket::new(icmp_buffer).unwrap();
    icmp_packet.populate(&icmp::Icmp {
        icmp_type: icmp::IcmpTypes::EchoRequest,
        icmp_code: icmp::IcmpCode::new(0),
        checksum: 0,
        payload: mk_payload(id, icmp_seq),
    });

    icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));
    icmp_packet.consume_to_immutable()
}
