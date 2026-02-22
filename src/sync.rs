use crate::*;
use std::net::UdpSocket;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::num::Wrapping;
use std::time::Duration;

/// Synchronous SNMPv2 client.
pub struct SyncSession {
    socket: UdpSocket,
    security: SnmpSecurity,
    #[cfg(feature = "v3")]
    secbuf: crate::v3::SecurityBuf,
    req_id: Wrapping<i32>,
    send_pdu: pdu::Buf,
    recv_buf: Box<[u8; BUFFER_SIZE]>,
    #[cfg(feature = "v3")]
    v3_msg_id: Wrapping<i32>,
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
            recv_buf: Box::new([0; BUFFER_SIZE]),
            #[cfg(feature = "v3")]
            secbuf: crate::v3::SecurityBuf::default(),
            #[cfg(feature = "v3")]
            v3_msg_id: Wrapping(1),
        })
    }

    #[cfg(feature = "v3")]
    fn check_security(&mut self, repeat: u32) -> SnmpResult<()> {
        if self.security.credentials.version() == 3 {
            if let SnmpCredentials::V3(sec) = &mut self.security.credentials {
                if !self.security.state.need_init() {
                    self.security.state.correct_authoritative_engine_time();
                    return Ok(());
                }
            }
            let req_id = self.req_id.0;
            v3::build_init(req_id, self.v3_msg_id.0, &mut self.send_pdu);
            let recv_len = self.send_and_recv_repeat(repeat)?;
            self.req_id += Wrapping(1);
            let pdu_bytes = &self.recv_buf[..recv_len];
            if let SnmpCredentials::V3(sec) = &self.security.credentials {
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
                Some(&mut self.secbuf),
            )?;
        }
        #[cfg(not(feature = "v3"))]
        {
            resp = SnmpPdu::from_bytes(pdu_bytes)?;
        }
        Ok(resp)
    }

    fn send_and_recv(&mut self) -> SnmpResult<usize> {
        match self.socket.send(&self.send_pdu[..]) {
            Ok(_pdu_len) => {
                #[cfg(feature = "v3")]
                {
                    self.v3_msg_id += Wrapping(1);
                }
                match self.socket.recv(&mut self.recv_buf[..]) {
                    Ok(len) => Ok(len),
                    Err(e) => Err(SnmpError::ReceiveError(format!("{}", e))),
                }
            }
            Err(e) => Err(SnmpError::SendError(format!("{}", e))),
        }
    }

    pub fn send_and_recv_repeat(&mut self, repeat: u32) -> SnmpResult<usize> {
        for _ in 1..repeat {
            if let Ok(n) = self.send_and_recv() {
                return Ok(n);
            }
        }
        self.send_and_recv()
    }

    pub fn get<ITM, ITMB>(&mut self, name: ITMB, repeat: u32) -> SnmpResult<SnmpPdu<'_>>
    where
        ITMB: std::borrow::Borrow<ITM> + Clone,
        ITM: VarbindOid,
    {
        #[cfg(feature = "v3")]
        {
            self.check_security(repeat)?;
            let mut err = SnmpError::Timeout;
            let req_id = self.req_id.0;
            self.req_id += Wrapping(1);
            for _ in 0..repeat {
                pdu::build_get(
                    &self.security,
                    req_id,
                    self.v3_msg_id.0,
                    name.clone(),
                    &mut self.send_pdu,
                )?;
                match self.send_and_recv() {
                    Err(e) => {
                        err = e;
                        match err {
                            SnmpError::Timeout => continue,
                            SnmpError::RequestIdMismatch => continue, //late reply
                            other => return Err(other),
                        }
                    }
                    Ok(result) => return self.getpdu(result),
                }
            }
            Err(err)
        }
        #[cfg(not(feature = "v3"))]
        {
            let req_id = self.req_id.0;
            pdu::build_get(&self.security, req_id, req_id, name, &mut self.send_pdu)?;
            let recv_len = self.send_and_recv_repeat(repeat)?;
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

    pub fn getnext<'slf, ITM, ITMB, VLS>(
        &'slf mut self,
        names: VLS,
        repeat: u32,
    ) -> SnmpResult<SnmpPdu<'slf>>
     where
        VLS: std::iter::IntoIterator<Item = ITMB> + Clone,
        VLS::IntoIter: DoubleEndedIterator,
        ITMB: std::borrow::Borrow<ITM>,
        ITM: VarbindOid,
    {
        #[cfg(feature = "v3")]
        {
            self.check_security(repeat)?;
            let mut err = SnmpError::Timeout;
            let req_id = self.req_id.0;
            self.req_id += Wrapping(1);
            for _ in 0..repeat {
                pdu::build_getnext(
                    &self.security,
                    req_id,
                    self.v3_msg_id.0,
                    names.clone(),
                    &mut self.send_pdu,
                )?;
                match self.send_and_recv() {
                    Err(e) => {
                        err = e;
                        match err {
                            SnmpError::Timeout => continue,
                            SnmpError::RequestIdMismatch => continue, //late reply
                            other => return Err(other),
                        }
                    }
                    Ok(result) => return self.getpdu(result),
                }
            }
            Err(err)
        }
        #[cfg(not(feature = "v3"))]
        {
            let req_id = self.req_id.0;
            pdu::build_getnext(&self.security, req_id, req_id, names, &mut self.send_pdu)?;
            let recv_len = self.send_and_recv_repeat(repeat)?;
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
    pub fn getbulk<ITM, ITMB, VLS>(
        &mut self,
        names: VLS,
        non_repeaters: u32,
        max_repetitions: u32,
        repeat: u32,
    ) -> SnmpResult<SnmpPdu<'_>>
    where
        VLS: std::iter::IntoIterator<Item = ITMB> + Clone,
        VLS::IntoIter: DoubleEndedIterator,
        ITMB: std::borrow::Borrow<ITM>,
        ITM: VarbindOid,
    {
        #[cfg(feature = "v3")]
        {
            self.check_security(repeat)?;
            let mut err = SnmpError::Timeout;
            let req_id = self.req_id.0;
            self.req_id += Wrapping(1);
            for _ in 0..repeat {
                pdu::build_getbulk(
                    &self.security,
                    req_id,
                    self.v3_msg_id.0,
                    names.clone(),
                    non_repeaters,
                    max_repetitions,
                    &mut self.send_pdu,
                )?;
                match self.send_and_recv() {
                    Err(e) => {
                        err = e;
                        match err {
                            SnmpError::Timeout => continue,
                            SnmpError::RequestIdMismatch => continue, //late reply
                            other => return Err(other),
                        }
                    }
                    Ok(result) => return self.getpdu(result),
                }
            }
            Err(err)
        }
        #[cfg(not(feature = "v3"))]
        {
            let req_id = self.req_id.0;
            pdu::build_getbulk(
                &self.security,
                req_id,
                req_id,
                names,
                non_repeaters,
                max_repetitions,
                &mut self.send_pdu,
            )?;
            let recv_len = self.send_and_recv_repeat(repeat)?;
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
    pub fn set<'slf, ITM, ITMB, VLS>(
        &'slf mut self,
        values: VLS,
        repeat: u32,
    ) -> SnmpResult<SnmpPdu<'slf>>
    where
        VLS: std::iter::IntoIterator<Item = ITMB> + Clone,
        VLS::IntoIter: DoubleEndedIterator,
        ITMB: std::borrow::Borrow<ITM>,
        ITM: VarbindOid,
    {
        #[cfg(feature = "v3")]
        {
            self.check_security(repeat)?;
            let mut err = SnmpError::Timeout;
            let req_id = self.req_id.0;
            self.req_id += Wrapping(1);
            for _ in 0..repeat {
                pdu::build_set(
                    &self.security,
                    req_id,
                    self.v3_msg_id.0,
                    values.clone(),
                    &mut self.send_pdu,
                )?;
                match self.send_and_recv() {
                    Err(e) => {
                        err = e;
                        match err {
                            SnmpError::Timeout => continue,
                            SnmpError::RequestIdMismatch => continue, //late reply
                            other => return Err(other),
                        }
                    }
                    Ok(result) => return self.getpdu(result),
                }
            }
            Err(err)
        }
        #[cfg(not(feature = "v3"))]
        {
            let req_id = self.req_id.0;
            pdu::build_set(&self.security, req_id, req_id, values, &mut self.send_pdu)?;
            let recv_len = self.send_and_recv_repeat(repeat)?;
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
}
