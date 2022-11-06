use deku::prelude::*;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::{ffi::CString, io::Write, net::TcpStream, time::Duration};

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct BasicPacket {
    size: i32,
    id: i32,
    packet_type: i32,
    #[deku(until = "|v:&u8| *v == 0x00")]
    body: Vec<u8>,
    terminator: u8,
}

fn auth_request(id: i32, pass: &str) -> Result<BasicPacket, anyhow::Error> {
    let body_size: i32 = i32::try_from(pass.as_bytes().to_vec().len())?;
    // len(id) + len(packet_type) + length of password
    let size = 4 + 4 + body_size + 1;

    Ok(BasicPacket {
        size: size,
        id: id,
        packet_type: 3,
        body: CString::new(pass)?.into_bytes_with_nul().to_vec(),
        terminator: 0,
    })
}

pub fn rcon_query(addr: &str, password: &str) -> Result<(), anyhow::Error> {
    let a: SocketAddr = addr.parse()?;
    let mut stream = TcpStream::connect_timeout(&a, Duration::new(5, 0))?;
    println!("Connected to {}", addr);
    //stream.set_write_timeout(Some(Duration::new(5, 0)))?;
    let auth_packet = auth_request(1, password)?;
    let data: Vec<u8> = auth_packet.try_into()?;
    stream.write(&data)?;
    println!("written data to tcp stream");
    let mut buff: [u8; 2048] = [0; 2048];
    stream.read(&mut buff)?;
    println!("{:x?}", buff);
    let (_rest, packet) = BasicPacket::from_bytes((buff.as_ref(), 0))?;
    println!("{:?}", packet);
    println!("{:?}", CString::from_vec_with_nul(packet.body)?);
    Ok(())
}

#[cfg(test)]
mod test {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn test_encoding() -> Result<(), anyhow::Error> {
        let test_data: Vec<u8> = i32::to_le_bytes(1)
            .into_iter()
            .chain(i32::to_le_bytes(2))
            .into_iter()
            .chain(i32::to_le_bytes(3))
            .into_iter()
            .chain(vec![b'a', b'b', b'c', 0x00, 0x00])
            .chain([0; 10])
            .collect();
        //let test_data = vec![1_i32, 2_i32, 3_i32, b'a', b'b', b'c', 0x00];
        let (_rest, bp) = BasicPacket::from_bytes((test_data.as_ref(), 0))?;
        println!("{:?}", bp);
        assert_eq!(
            BasicPacket {
                size: 1,
                id: 2,
                packet_type: 3,
                body: CString::new(b"abc".to_vec())?.into_bytes_with_nul(),
                terminator: 0x00_u8,
            },
            bp,
        );
        Ok(())
    }
}
