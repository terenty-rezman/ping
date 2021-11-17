use std::net::{SocketAddr, ToSocketAddrs};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

trait ToBigEndian {
    fn to_be_vec(&self) -> Vec<u8>;
}

impl ToBigEndian for u8 {
    fn to_be_vec(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl ToBigEndian for u16 {
    fn to_be_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
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

    fn push<T>(&mut self, data: T)
    where
        T: ToBigEndian,
    {
        self.data.append(&mut data.to_be_vec());
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
        let as_u16: u16 = (two_u8[0] as u16) << 8 + two_u8[1];
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
    packed.push(h.ty);
    packed.push(h.code);
    packed.push(h.checksum);
    packed.push(h.id);
    packed.push(h.seq_num);
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

    return packet
}

fn main() {

    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    let remote = "www.google.com".to_socket_addrs().unwrap().next().unwrap();

    let packet = create_echo_request_msg(0, 1, "ping");

    socket.send_to(&packet, &SockAddr::from(remote));


    println!("{:?}", packet);
}
