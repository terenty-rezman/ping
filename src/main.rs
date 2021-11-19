use std::env;
use std::io::Result;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use std::{thread, time};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

trait BigEndianConvert {
    fn to_be_vec(&self) -> Vec<u8>;
    fn from_be_slice(packed: &[u8]) -> Self;
}

impl BigEndianConvert for u8 {
    fn to_be_vec(&self) -> Vec<u8> {
        vec![*self]
    }

    fn from_be_slice(packed: &[u8]) -> u8 {
        packed[0]
    }
}

use duplicate::duplicate;

#[duplicate(
    int_type;
    [u16];
    [u32]
)]
impl BigEndianConvert for int_type {
    fn to_be_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn from_be_slice(packed: &[u8]) -> Self {
        Self::from_be_bytes(packed.try_into().unwrap())
    }
}

#[derive(Debug)]
struct PackedBytes {
    data: Vec<u8>,
}

impl PackedBytes {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn from_vec(packet: Vec<u8>) -> Self {
        Self { data: packet }
    }

    fn pack<T>(&mut self, data: T)
    where
        T: BigEndianConvert,
    {
        self.data.append(&mut data.to_be_vec());
    }

    fn unpack<T>(&mut self) -> T
    where
        T: BigEndianConvert,
    {
        // take last n=sizeof(T) elements from vector and unpack them from network (big endian order)
        let data_len = self.data.len();
        let last_n_items = self.data.split_off(data_len - core::mem::size_of::<T>());
        T::from_be_slice(&last_n_items)
    }
}

fn checksum(bytes: &Vec<u8>) -> u16 {
    let mut bytes = bytes.clone();

    // ensure bytes len is even
    if bytes.len() % 2 != 0 {
        bytes.push(0);
    }

    let mut sum = 0;

    // calc ICMP checksum
    // https://stackoverflow.com/a/20247802/13847352
    for i in (0..bytes.len()).step_by(2) {
        let two_u8 = &bytes[i..i + 2];
        let as_u16: u16 = ((two_u8[0] as u16) << 8) + two_u8[1] as u16;
        sum += as_u16;
    }
    // ones complement
    let sum = !sum;
    sum
}

struct ICMPheader {
    ty: u8,
    code: u8,
    checksum: u16,
    id: u16,
    seq_num: u16,
}

impl ICMPheader {
    fn from_packed_bytes(packed: PackedBytes) -> ICMPheader {
        let mut packed = packed;
        ICMPheader {
            seq_num: packed.unpack(),
            id: packed.unpack(),
            checksum: packed.unpack(),
            code: packed.unpack(),
            ty: packed.unpack(),
        }
    }
}

const ECHO_REQUEST_HEADER: ICMPheader = ICMPheader {
    ty: 8,
    code: 0,
    checksum: 0,
    id: 0,
    seq_num: 1,
};

fn create_echo_request_header(id: u16, seq_num: u16, checksum: u16) -> ICMPheader {
    ICMPheader {
        checksum,
        id,
        seq_num,
        ..ECHO_REQUEST_HEADER
    }
}

fn pack_header(h: ICMPheader) -> PackedBytes {
    let mut packed = PackedBytes::new();
    packed.pack(h.ty);
    packed.pack(h.code);
    packed.pack(h.checksum);
    packed.pack(h.id);
    packed.pack(h.seq_num);
    packed
}

fn create_echo_request_msg(id: u16, seq_num: u16, msg: &str) -> Vec<u8> {
    // create icmp packet without checksum
    let h = create_echo_request_header(id, seq_num, 0);
    let packed_header = pack_header(h);
    let mut packed_msg = msg.as_bytes().to_vec();

    let mut packet: Vec<u8> = packed_header.data;
    packet.append(&mut packed_msg);

    // calc checksum for the packet
    let checksum = checksum(&packet);

    // now create packet with correct checksum
    let h = create_echo_request_header(id, seq_num, checksum);
    let packed_header = pack_header(h);
    let mut packed_msg = msg.as_bytes().to_vec();

    let mut packet: Vec<u8> = packed_header.data;
    packet.append(&mut packed_msg);

    return packet;
}

struct IPheader {
    version_ihl: u8,
    tos: u8,
    total_lenght: u16,
    identification: u16,
    flags_fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    source_address: u32,
    destination_address: u32,
}

impl IPheader {
    fn from_packed_bytes(packed: PackedBytes) -> IPheader {
        let mut packed = packed;
        IPheader {
            destination_address: packed.unpack(),
            source_address: packed.unpack(),
            header_checksum: packed.unpack(),
            protocol: packed.unpack(),
            ttl: packed.unpack(),
            flags_fragment_offset: packed.unpack(),
            identification: packed.unpack(),
            total_lenght: packed.unpack(),
            tos: packed.unpack(),
            version_ihl: packed.unpack(),
        }
    }
}

fn get_icmp_error_msg(icmp_header: &ICMPheader) -> Option<&'static str> {
    // https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    return match icmp_header.ty {
        3 => match icmp_header.code {
            0 => Some("Destination network unreachable"),
            1 => Some("Destination host unreachable"),
            2 => Some("Destination protocol unreachable"),
            3 => Some("Destination port unreachable"),
            4 => Some("Fragmentation required, and DF flag set"),
            5 => Some("Source route failed"),
            6 => Some("Destination network unknown"),
            7 => Some("Destination host unknown"),
            8 => Some("Source host isolated"),
            9 => Some("Network administratively prohibited"),
            10 => Some("Host administratively prohibited"),
            11 => Some("Network unreachable for ToS"),
            12 => Some("Host unreachable for ToS"),
            13 => Some("Communication administratively prohibited"),
            14 => Some("Host Precedence Violation"),
            15 => Some("Precedence cutoff in effect"),
            _ => None,
        },
        _ => None,
    };
}

fn do_one_ping(
    socket: &Socket,
    remote: &SocketAddr,
) -> Result<(Ipv4Addr, u8, Option<&'static str>)> {
    let echo_packet = create_echo_request_msg(0, 1, "ping");

    let bytes_sent = socket.send_to(&echo_packet, &SockAddr::from(remote.clone()))?;

    if bytes_sent != echo_packet.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "failed to send request",
        ));
    }

    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buffer: [u8; 4096] = [0; 4096];
    let buffer_ptr = &mut buffer as *mut [u8; 4096] as *mut [MaybeUninit<u8>; 4096];
    let buffer_ref = unsafe { &mut (*buffer_ptr) };

    let (len, _) = socket.recv_from(buffer_ref)?;

    // IP header
    let ip_header = buffer[..20].to_vec();
    let ip_header = IPheader::from_packed_bytes(PackedBytes::from_vec(ip_header));
    let source = Ipv4Addr::from(ip_header.source_address);

    // 20 - skip IP header start from ICMP header
    let recv_packet = buffer[20..len].to_vec();
    let icmp_header = recv_packet[..std::mem::size_of::<ICMPheader>()].to_vec();

    let icmp_header_unpacked = ICMPheader::from_packed_bytes(PackedBytes::from_vec(icmp_header));

    let icmp_error_response = get_icmp_error_msg(&icmp_header_unpacked);

    Ok((source, ip_header.ttl, icmp_error_response))
}

fn str_to_ip_address(host: &str) -> Result<(bool, SocketAddr)> {
    let host = host.to_string();
    let host = host + ":80";

    let remote_ip_address = host.to_socket_addrs()?.next().unwrap();
    let dns_resolved = host.chars().any(char::is_alphabetic);

    Ok((dns_resolved, remote_ip_address))
}

fn main() {
    let mut args: Vec<String> = env::args().collect();

    println!();

    if args.len() != 2 {
        println!("Usage: ping target_name\n");
        return;
    }

    let remote_host = args.remove(1);
    let (dns_resolved, remote_ip_address) = match str_to_ip_address(&remote_host) {
        Ok((dns_resolved, addr)) => (dns_resolved, addr),
        Err(error) => {
            println!("{}", &error);
            return;
        }
    };

    // remove :80 suffix from address str
    let remote_ip_str = remote_ip_address
        .to_string()
        .strip_suffix(":80")
        .unwrap()
        .to_string();

    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();

    if dns_resolved {
        println!("Pinging {} {}:", remote_host, remote_ip_str);
    } else {
        println!("Pinging {}:", remote_ip_str);
    }

    for _ in 0..4 {
        let now = time::Instant::now();

        match do_one_ping(&socket, &remote_ip_address) {
            Ok((host, ttl, icmp_error_response)) => {
                let elapsed = now.elapsed();

                // if icmp reported some error -> print it 
                match icmp_error_response {
                    Some(err_str) => println!("Reply from {}: {}", host, err_str),
                    None => println!(
                        "Reply from {}: time={}ms TTL={}",
                        host,
                        elapsed.as_millis(),
                        ttl
                    ),
                }
            }
            Err(error) => match error.kind() {
                std::io::ErrorKind::TimedOut => println!("Request timed out."),
                _ => println!("{}", error),
            },
        }

        // sleep up to one sec between pings
        let elapsed = now.elapsed();
        let inverval = time::Duration::from_secs(1);
        if elapsed < inverval {
            thread::sleep(inverval - elapsed);
        }
    }
}
