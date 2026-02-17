use crate::*;
use std::net::UdpSocket;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::num::Wrapping;
use std::time::Duration;

/// Synchronous SNMPv2 client.
pub struct SyncSession {
    socket: UdpSocket,
    security: SnmpSecurity,
    req_id: Wrapping<i32>,
    send_pdu: pdu::Buf,
    recv_buf: [u8; BUFFER_SIZE],
}

impl SyncSession {
    pub fn new<SA>(
        destination: SA,
        creds: SnmpCredentials,
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> SnmpResult<Self>
    where
        SA: ToSocketAddrs,
    {
        let socket = match destination.to_socket_addrs()?.next() {
            Some(SocketAddr::V4(_)) => UdpSocket::bind((Ipv4Addr::new(0, 0, 0, 0), 0))?,
            Some(SocketAddr::V6(_)) => UdpSocket::bind((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0))?,
            None => panic!("empty list of socket addrs"),
        };
        socket.set_read_timeout(timeout)?;
        socket.connect(destination)?;
        Ok(SyncSession {
            socket,
            security: creds.into(),
            req_id: Wrapping(starting_req_id),
            send_pdu: pdu::Buf::default(),
            recv_buf: [0; 4096],
        })
    }

    #[cfg(feature = "v3")]
    fn check_security(&mut self) -> SnmpResult<()> {
        if self.security.credentials.version() == 3 {
            if let SnmpCredentials::V3(sec) = &mut self.security.credentials {
                if !self.security.state.need_init() {
                    self.security.state.correct_authoritative_engine_time();
                    return Ok(());
                }
                let req_id = self.req_id.0;
                v3::build_init(req_id, &mut self.send_pdu);
                let recv_len = Self::send_and_recv_repeat(
                    &self.socket,
                    &self.send_pdu,
                    &mut self.recv_buf[..],
                    1,
                )?;
                self.req_id += Wrapping(1);
                let pdu_bytes = &self.recv_buf[..recv_len];
                v3::parse_init_report(pdu_bytes, sec, &mut self.security.state)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn getpdu<'slf>(&'slf mut self, buflen: usize) -> SnmpResult<SnmpPdu<'slf>> {
        let pdu_bytes = &self.recv_buf[..buflen];
        let resp;
        #[cfg(feature = "v3")]
        {
            resp = SnmpPdu::from_bytes_with_security(
                pdu_bytes,
                self.security.credentials.v3(),
                Some(&mut self.security.state),
            )?;
        }
        #[cfg(not(feature = "v3"))]
        {
            resp = SnmpPdu::from_bytes(pdu_bytes)?;
        }
        Ok(resp)
    }

    fn send_and_recv(socket: &UdpSocket, pdu: &pdu::Buf, out: &mut [u8]) -> SnmpResult<usize> {
        match socket.send(&pdu[..]) {
            Ok(_pdu_len) => match socket.recv(out) {
                Ok(len) => Ok(len),
                Err(e) => Err(SnmpError::ReceiveError(format!("{}", e))),
            },
            Err(e) => Err(SnmpError::SendError(format!("{}", e))),
        }
    }

    pub fn send_and_recv_repeat(
        socket: &UdpSocket,
        pdu: &pdu::Buf,
        out: &mut [u8],
        repeat: u32,
    ) -> SnmpResult<usize> {
        for _ in 1..repeat {
            if let Ok(n) = Self::send_and_recv(socket, pdu, out) {
                return Ok(n);
            }
        }
        Self::send_and_recv(socket, pdu, out)
    }

    pub fn get<'slf>(&'slf mut self, name: &[u32], repeat: u32) -> SnmpResult<SnmpPdu<'slf>> {
        #[cfg(feature = "v3")]
        self.check_security()?;
        let req_id = self.req_id.0;
        pdu::build_get(&self.security, req_id, name, &mut self.send_pdu)?;
        let recv_len = Self::send_and_recv_repeat(
            &self.socket,
            &self.send_pdu,
            &mut self.recv_buf[..],
            repeat,
        )?;
        self.req_id += Wrapping(1);
        let resp = self.getpdu(recv_len)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        Ok(resp)
    }

    pub fn getnext<'slf>(&'slf mut self, name: &[u32], repeat: u32) -> SnmpResult<SnmpPdu<'slf>> {
        #[cfg(feature = "v3")]
        self.check_security()?;
        let req_id = self.req_id.0;
        pdu::build_getnext(&self.security, req_id, name, &mut self.send_pdu)?;
        let recv_len = Self::send_and_recv_repeat(
            &self.socket,
            &self.send_pdu,
            &mut self.recv_buf[..],
            repeat,
        )?;
        self.req_id += Wrapping(1);
        let resp = self.getpdu(recv_len)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        Ok(resp)
    }
    pub fn getbulk<'slf, NAMES, ITM>(
        &'slf mut self,
        names: NAMES,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> SnmpResult<SnmpPdu<'slf>>
    where
        NAMES: std::iter::IntoIterator<Item = ITM>,
        NAMES::IntoIter: DoubleEndedIterator,
        ITM: crate::VarbindOid,
    {
        #[cfg(feature = "v3")]
        self.check_security()?;
        let req_id = self.req_id.0;
        pdu::build_getbulk(
            &self.security,
            req_id,
            names,
            non_repeaters,
            max_repetitions,
            &mut self.send_pdu,
        )?;
        let recv_len = Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf[..])?;
        self.req_id += Wrapping(1);
        let resp = self.getpdu(recv_len)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        Ok(resp)
    }

    /// # Panics if any of the values are not one of these supported types:
    ///   - `Boolean`
    ///   - `Null`
    ///   - `Integer`
    ///   - `OctetString`
    ///   - `ObjectIdentifier`
    ///   - `IpAddress`
    ///   - `Counter32`
    ///   - `Unsigned32`
    ///   - `Timeticks`
    ///   - `Opaque`
    ///   - `Counter64`
    pub fn set<'slf>(
        &'slf mut self,
        values: &[(&[u32], Value)],
        repeat: u32,
    ) -> SnmpResult<SnmpPdu<'slf>> {
        #[cfg(feature = "v3")]
        self.check_security()?;
        let req_id = self.req_id.0;
        pdu::build_set(&self.security, req_id, values, &mut self.send_pdu)?;
        let recv_len = Self::send_and_recv_repeat(
            &self.socket,
            &self.send_pdu,
            &mut self.recv_buf[..],
            repeat,
        )?;
        self.req_id += Wrapping(1);
        let resp = self.getpdu(recv_len)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        Ok(resp)
    }
}
