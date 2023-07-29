use pnet::{
    packet::{icmp::*, icmpv6::*, *},
    transport::*,
};
use std::{
    error::Error,
    fmt, mem,
    net::{IpAddr, Ipv6Addr},
    process, time, vec,
};

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

// Reference: https://github.com/Daniel-Liu-c0deb0t/9S

pub struct Pinger {
    t_addr: IpAddr,

    payload_size: usize,

    total_pings: u128,
    lost_packets: usize,
    rtt_total: u128,
    avg_rtt: time::Duration,

    tx: TransportSender,
    rx: TransportReceiver,

    timeout: time::Duration,

    id: u16,
    icmp_seq: u16,
}

pub struct EchoResponse {
    send_time: u128,
    rtt: time::Duration,
    id: u16,
    icmp_seq: u16,
    s_addr: IpAddr,
    packet_metadata_size: usize,
    payload: Vec<u8>,
}

impl EchoResponse {
    /// do whatever the fuck u want with it
    pub fn send_time(&self) -> u128 {
        self.send_time
    }

    pub fn rtt(&self) -> time::Duration {
        self.rtt
    }
    pub fn id(&self) -> u16 {
        self.id
    }
    pub fn icmp_seq(&self) -> u16 {
        self.icmp_seq
    }
    pub fn s_addr(&self) -> IpAddr {
        self.s_addr
    }
    pub fn packet_metdata_size(&self) -> usize {
        self.packet_metadata_size
    }
    /// Might be wrong. but  i think the packet size is packet_metdata_size (might not even be the real size of metdata) + payload_size
    pub fn packet_size(&self) -> usize{
        self.packet_metadata_size + self.payload.len()
    } 
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
}

#[derive(Debug)]
pub struct PingError {
    details: String,
    err: PingEnum,
}

impl PingError {
    fn new(msg: &str, eum: PingEnum) -> PingError {
        PingError {
            details: msg.to_owned(),
            err: eum,
        }
    }
    pub fn err(&self) -> PingEnum {
        self.err.clone()
    }
}

impl fmt::Display for PingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for PingError {
    fn description(&self) -> &str {
        &self.details
    }
}

#[derive(Debug, Clone)]
pub enum PingEnum {
    Unknown,
    NoData,
    InvalidIcmpCode,
    DestinationUnreachable,
    SelfPing,
}

impl Pinger {
    /// New pinger struct

    pub fn new(addr: IpAddr, timeout: time::Duration, payload_size: usize, ttl: u8) -> Pinger {
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
                tx.set_ttl(ttl)
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
            payload_size,
            total_pings: 0,
            lost_packets: 0,
            rtt_total: 0,
            avg_rtt: time::Duration::new(0, 0),
            tx,
            rx,
            id: process::id() as u16,
            icmp_seq: 0,
            timeout,
        }
    }

    /// Pings once to self.t_addr

    pub fn ping_throw(&mut self) -> Result<EchoResponse, PingError> {
        let mut buf = vec![0u8; self.payload_size];
        let before_send_time = time::Instant::now();
        match self.t_addr {
            IpAddr::V4(_) => {
                let packet = make_icmp_packet(&mut buf, self.id, self.icmp_seq);
                self.tx
                    .send_to(packet, self.t_addr)
                    .pretty_unwrap(Some("Failed to tx.send_to"));
                return self.v4_recv(before_send_time);
            }
            IpAddr::V6(dest) => {
                let packet = make_icmpv6_packet(dest, &mut buf, self.id, self.icmp_seq);
                self.tx
                    .send_to(packet, self.t_addr)
                    .pretty_unwrap(Some("Failed to tx.send_to"));
                return self.v6_recv(before_send_time);
            }
        }
    }

    fn calc_avg_rtt(&mut self, before_send: time::Instant) {
        let now = time::Instant::now();
        self.rtt_total += now.duration_since(before_send).as_nanos();
        self.avg_rtt = time::Duration::from_nanos((self.rtt_total / (self.total_pings)) as u64);
    }

    fn v4_recv(&mut self, before_send: time::Instant) -> Result<EchoResponse, PingError> {
        let mut tr = icmp_packet_iter(&mut self.rx);
        let (resp_packet, resp_ip) = match tr.next_with_timeout(self.timeout) {
            Ok(t) => match t {
                Some(s) => s,
                None => {
                    return Err(PingError::new(
                        "Timeout? who knows. pnet wont fucking tell",
                        PingEnum::NoData,
                    ));
                }
            },
            Err(e) => {
                return Err(PingError::new(e.to_string().as_str(), PingEnum::Unknown));
            }
        };
        let payload = echo_parse(
            resp_packet.payload(),
            resp_packet.packet_size(),
            resp_ip,
            before_send,
        );

        self.total_pings += 1;

        match resp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                self.icmp_seq += 1;
            }
            IcmpTypes::DestinationUnreachable => {
                self.lost_packets += 1;
                // probably wont get used
                return Err(PingError::new(
                    "Destination Unreachable",
                    PingEnum::DestinationUnreachable,
                ));
            }
            IcmpTypes::EchoRequest => {
                return Err(PingError::new(
                    "Dont ping yourself would ya?",
                    PingEnum::SelfPing,
                ));
            }
            _ => {
                self.lost_packets += 1;
                return Err(PingError::new(
                    format!("Invalid ICMP Echo code: {}", resp_packet.get_icmp_code().0).as_str(),
                    PingEnum::InvalidIcmpCode,
                ));
            }
        };

        self.calc_avg_rtt(before_send);

        Ok(payload)
    }

    fn v6_recv(&mut self, before_send: time::Instant) -> Result<EchoResponse, PingError> {
        let mut tr = icmpv6_packet_iter(&mut self.rx);
        let (resp_packet, resp_ip) = match tr.next_with_timeout(self.timeout) {
            Ok(t) => match t {
                Some(s) => s,
                None => {
                    return Err(PingError::new(
                        "Timeout? who knows. pnet wont fucking tell",
                        PingEnum::NoData,
                    ));
                }
            },
            Err(e) => {
                return Err(PingError::new(e.to_string().as_str(), PingEnum::Unknown));
            }
        };
        let payload = echo_parse(
            resp_packet.payload(),
            resp_packet.packet_size(),
            resp_ip,
            before_send,
        );

        self.total_pings += 1;

        match resp_packet.get_icmpv6_type() {
            Icmpv6Types::EchoReply => {
                self.icmp_seq += 1;
            }
            Icmpv6Types::DestinationUnreachable => {
                self.lost_packets += 1;
                // probably wont get used
                return Err(PingError::new(
                    "Destination Unreachable",
                    PingEnum::DestinationUnreachable,
                ));
            }
            Icmpv6Types::EchoRequest => {
                return Err(PingError::new(
                    "Dont ping yourself would ya?",
                    PingEnum::SelfPing,
                ));
            }
            _ => {
                self.lost_packets += 1;
                return Err(PingError::new(
                    format!(
                        "Invalid ICMP Echo code: {}",
                        resp_packet.get_icmpv6_code().0
                    )
                    .as_str(),
                    PingEnum::InvalidIcmpCode,
                ));
            }
        };

        self.calc_avg_rtt(before_send);

        Ok(payload)
    }

    pub fn set_target(&mut self, target: IpAddr) {
        self.t_addr = target
    }

    pub fn total_pings(&self) -> u128 {
        self.total_pings
    }

    pub fn lost_packets(&self) -> usize {
        self.lost_packets
    }

    pub fn t_addr(&self) -> IpAddr {
        self.t_addr
    }

    pub fn avg_rtt(&self) -> time::Duration {
        self.avg_rtt
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn icmp_seq(&self) -> u16 {
        self.icmp_seq
    }
}

fn echo_parse(
    payload: &[u8],
    packet_size: usize,
    ip: IpAddr,
    before_send: time::Instant,
) -> EchoResponse {
    // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
    let send_time = unsafe {
        let num = 0u128;
        let mut arr = mem::transmute::<u128, [u8; 16]>(num);
        arr.copy_from_slice(&payload[4..20]);
        mem::transmute::<[u8; 16], u128>(arr)
    };

    let id = payload[0] as u16 + ((payload[1] as u16) << 8); // identifier
    let icmp_seq = payload[2] as u16 + ((payload[3] as u16) << 8);
    let now = time::Instant::now();
    EchoResponse {
        send_time,
        rtt: now.duration_since(before_send),
        id,
        icmp_seq,
        s_addr: ip,
        packet_metadata_size: packet_size,
        payload: Vec::from(payload),
    }
}

fn mk_payload(id: u16, icmp_seq: u16) -> Vec<u8> {
    let now = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .pretty_unwrap(Some("mk_payload systime unix epoch"))
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
    if icmp_buffer.len() < 24 {
        panic!("cmonnnnnnnn make sure its at least 24 bytes!!!!")
    }
    let mut icmp_packet = icmp::MutableIcmpPacket::new(icmp_buffer).unwrap();
    icmp_packet.populate(&icmp::Icmp {
        icmp_type: IcmpTypes::EchoRequest,
        icmp_code: IcmpCode::new(0),
        checksum: 0,
        payload: mk_payload(id, icmp_seq),
    });

    icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));
    icmp_packet.consume_to_immutable()
}

fn make_icmpv6_packet(
    dest: Ipv6Addr,
    icmp_buffer: &mut [u8],
    id: u16,
    icmp_seq: u16,
) -> icmpv6::Icmpv6Packet {
    if icmp_buffer.len() < 24 {
        panic!("cmonnnnnnnn make sure its at least 24 bytes!!!!")
    }
    let mut icmp_packet = icmpv6::MutableIcmpv6Packet::new(icmp_buffer).unwrap();
    icmp_packet.populate(&icmpv6::Icmpv6 {
        icmpv6_type: Icmpv6Types::EchoRequest,
        icmpv6_code: Icmpv6Code::new(0),
        checksum: 0,
        payload: mk_payload(id, icmp_seq),
    });
    icmp_packet.set_checksum(icmpv6::checksum(
        
        &icmp_packet.to_immutable(),
        &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        &dest,
    ));
    icmp_packet.consume_to_immutable()
}
