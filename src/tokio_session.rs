use crate::{
    pdu, SnmpCredentials, SnmpError, SnmpPdu, SnmpResult, SnmpSecurity, VarbindOid, BUFFER_SIZE,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::Wrapping;
use tokio::io;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};
use tokio::time::{timeout, Duration};

/// Simple asynchronous SNMP client for Tokio
pub struct TokioSession {
    socket: UdpSocket,
    security: SnmpSecurity,
    req_id: Wrapping<i32>,
    send_pdu: pdu::Buf,
    recv_buf: Box<[u8; BUFFER_SIZE]>,
    #[cfg(feature = "v3")]
    secbuf: crate::v3::SecurityBuf,
    #[cfg(feature = "v3")]
    v3_msg_id: Wrapping<i32>,
}

impl TokioSession {
    pub async fn new<SA>(
        destination: SA,
        credentials: SnmpCredentials,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        let socket = match lookup_host(&destination).await?.next() {
            Some(SocketAddr::V4(_)) => UdpSocket::bind((Ipv4Addr::new(0, 0, 0, 0), 0)).await?,
            Some(SocketAddr::V6(_)) => {
                UdpSocket::bind((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0)).await?
            }
            None => panic!("empty list of socket addrs"),
        };

        socket.connect(destination).await?;
        Ok(Self {
            socket,
            security: credentials.into(),
            req_id: Wrapping(starting_req_id),
            send_pdu: pdu::Buf::default(),
            recv_buf: Box::new([0; BUFFER_SIZE]),
            #[cfg(feature = "v3")]
            secbuf: crate::v3::SecurityBuf::default(),
            #[cfg(feature = "v3")]
            v3_msg_id: Wrapping(1),
        })
    }
    pub fn last_req_id(&self) -> i32 {
        self.req_id.0
    }
    pub fn set_last_req_id(&mut self, reqid: i32) {
        self.req_id.0 = reqid;
    }
    /*
    pub fn snmp_version(&self) -> i32 {
        self.security.version
    }
    pub fn set_snmp_version(&mut self, v: i32) -> SnmpResult<()> {
        if v == 1 || v == 2 {
            self.version = v;
            Ok(())
        } else {
            Err(SnmpError::ValueOutOfRange)
        }
    }
    pub fn snmp_community(&self) -> &Vec<u8> {
        &self.community
    }
    pub fn set_snmp_community(&mut self, community: &[u8]) -> SnmpResult<()> {
        if community.is_empty() {
            return Err(SnmpError::CommunityMismatch);
        }
        self.community.resize(community.len(), 0);
        self.community.as_mut_slice().copy_from_slice(community);
        Ok(())
    }
    */
    async fn send_and_recv(&mut self) -> SnmpResult<usize> {
        match self.socket.send(&self.send_pdu[..]).await {
            Ok(_pdu_len) => {
                #[cfg(feature = "v3")]
                {
                    self.v3_msg_id += Wrapping(1);
                }
                match self.socket.recv(&mut self.recv_buf[..]).await {
                    Ok(len) => Ok(len),
                    Err(e) => Err(SnmpError::ReceiveError(format!("{}", e))),
                }
            }
            Err(e) => Err(SnmpError::SendError(format!("{}", e))),
        }
    }
    async fn send_and_recv_timeout(&mut self, reqtimeout: Duration) -> SnmpResult<usize> {
        match self.socket.send(&self.send_pdu[..]).await {
            Ok(_pdu_len) => {
                #[cfg(feature = "v3")]
                {
                    self.v3_msg_id += Wrapping(1);
                }
                match timeout(reqtimeout, self.socket.recv(&mut self.recv_buf[..])).await {
                    Err(_) => Err(SnmpError::Timeout),
                    Ok(r) => match r {
                        Ok(len) => Ok(len),
                        Err(e) => Err(SnmpError::ReceiveError(format!("{}", e))),
                    },
                }
            }
            Err(e) => Err(SnmpError::SendError(format!("{}", e))),
        }
    }

    async fn send_and_recv_repeat(&mut self, repeat: u32, timeout: Duration) -> SnmpResult<usize> {
        for _ in 1..repeat {
            match self.send_and_recv_timeout(timeout).await {
                Err(e) => {
                    match e {
                        SnmpError::Timeout => continue,
                        SnmpError::RequestIdMismatch => continue, //late reply
                        other => return Err(other),
                    }
                }
                Ok(result) => {
                    return Ok(result);
                }
            }
        }
        self.send_and_recv_timeout(timeout).await
    }
    #[cfg(feature = "v3")]
    async fn check_security(&mut self, repeat: u32, timeout: Duration) -> SnmpResult<()> {
        if self.security.credentials.version() == 3 {
            if let SnmpCredentials::V3(_) = &self.security.credentials {
                if !self.security.state.need_init() {
                    self.security.state.correct_authoritative_engine_time();
                    return Ok(());
                }
            }
            let req_id = self.req_id.0;
            crate::v3::build_init(req_id, self.v3_msg_id.0, &mut self.send_pdu);
            let recv_len = self.send_and_recv_repeat(repeat, timeout).await?;
            self.req_id += Wrapping(1);
            let pdu_bytes = &self.recv_buf[..recv_len];
            if let SnmpCredentials::V3(sec) = &self.security.credentials {
                crate::v3::parse_init_report(pdu_bytes, sec, &mut self.security.state)
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

    pub async fn get<ITM, ITMB>(
        &mut self,
        name: ITMB,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>>
    where
        ITMB: std::borrow::Borrow<ITM> + Clone,
        ITM: VarbindOid,
    {
        #[cfg(feature = "v3")]
        {
            self.check_security(repeat, timeout).await?;
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
                match self.send_and_recv_timeout(timeout).await {
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
            let recv_len = selfsend_and_recv_repeat(repeat, timeout).await?;
            self.req_id += Wrapping(1);
            let resp = self.getpdu(recv_len)?;
            if resp.message_type != SnmpMessageType::Response {
                return Err(SnmpError::AsnWrongType);
            }
            if resp.req_id != req_id {
                return Err(SnmpError::RequestIdMismatch);
            }
            /*
            if resp.community != &self.community[..] {
                return Err(SnmpError::CommunityMismatch);
            }
            */
            Ok(resp)
        }
    }
    pub async fn getmulti<ITM, ITMB, VLS>(
        &mut self,
        names: VLS,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>>
    where
        VLS: std::iter::IntoIterator<Item = ITMB> + Clone,
        VLS::IntoIter: DoubleEndedIterator,
        ITMB: std::borrow::Borrow<ITM>,
        ITM: VarbindOid,
    {
        #[cfg(feature = "v3")]
        {
            self.check_security(repeat, timeout).await?;
            let mut err = SnmpError::Timeout;
            let req_id = self.req_id.0;
            self.req_id += Wrapping(1);
            for _ in 0..repeat {
                pdu::build_getmulti(
                    &self.security,
                    req_id,
                    self.v3_msg_id.0,
                    names.clone(),
                    &mut self.send_pdu,
                )?;
                match self.send_and_recv_timeout(timeout).await {
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
            pdu::build_getmulti(&self.security, req_id, req_id, names, &mut self.send_pdu)?;
            let recv_len = selfsend_and_recv_repeat(repeat, timeout).await?;
            self.req_id += Wrapping(1);
            let resp = self.getpdu(recv_len)?;
            if resp.message_type != SnmpMessageType::Response {
                return Err(SnmpError::AsnWrongType);
            }
            if resp.req_id != req_id {
                return Err(SnmpError::RequestIdMismatch);
            }
            /*
            if resp.community != &self.community[..] {
                return Err(SnmpError::CommunityMismatch);
            }
            */
            Ok(resp)
        }
    }
    pub async fn getnext<ITM, ITMB>(
        &mut self,
        name: ITMB,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>>
    where
        ITMB: std::borrow::Borrow<ITM> + Clone,
        ITM: VarbindOid,
    {
        #[cfg(feature = "v3")]
        {
            self.check_security(repeat, timeout).await?;
            let mut err = SnmpError::Timeout;
            let req_id = self.req_id.0;
            self.req_id += Wrapping(1);
            for _ in 0..repeat {
                pdu::build_getnext(
                    &self.security,
                    req_id,
                    self.v3_msg_id.0,
                    name.clone(),
                    &mut self.send_pdu,
                )?;
                match self.send_and_recv_timeout(timeout).await {
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
            pdu::build_getnext(&self.security, req_id, req_id, name, &mut self.send_pdu)?;
            let recv_len = selfsend_and_recv_repeat(repeat, timeout).await?;
            self.req_id += Wrapping(1);
            let resp = self.getpdu(recv_len)?;
            if resp.message_type != SnmpMessageType::Response {
                return Err(SnmpError::AsnWrongType);
            }
            if resp.req_id != req_id {
                return Err(SnmpError::RequestIdMismatch);
            }
            /*
            if resp.community != &self.community[..] {
                return Err(SnmpError::CommunityMismatch);
            }
            */
            Ok(resp)
        }
    }
    pub async fn getbulk<ITM, ITMB, VLS>(
        &mut self,
        names: VLS,
        non_repeaters: u32,
        max_repetitions: u32,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>>
    where
        VLS: std::iter::IntoIterator<Item = ITMB> + Clone,
        VLS::IntoIter: DoubleEndedIterator,
        ITMB: std::borrow::Borrow<ITM>,
        ITM: VarbindOid,
    {
        #[cfg(feature = "v3")]
        {
            self.check_security(repeat, timeout).await?;
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
                match self.send_and_recv_timeout(timeout).await {
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
            let recv_len = selfsend_and_recv_repeat(repeat, timeout).await?;
            self.req_id += Wrapping(1);
            let resp = self.getpdu(recv_len)?;
            if resp.message_type != SnmpMessageType::Response {
                return Err(SnmpError::AsnWrongType);
            }
            if resp.req_id != req_id {
                return Err(SnmpError::RequestIdMismatch);
            }
            /*
            if resp.community != &self.community[..] {
                return Err(SnmpError::CommunityMismatch);
            }
            */
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
    pub async fn getset<ITM, ITMB, VLS>(
        &mut self,
        names: VLS,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>>
    where
        VLS: std::iter::IntoIterator<Item = ITMB> + Clone,
        VLS::IntoIter: DoubleEndedIterator,
        ITMB: std::borrow::Borrow<ITM>,
        ITM: VarbindOid,
    {
        #[cfg(feature = "v3")]
        {
            self.check_security(repeat, timeout).await?;
            let mut err = SnmpError::Timeout;
            let req_id = self.req_id.0;
            self.req_id += Wrapping(1);
            for _ in 0..repeat {
                pdu::build_set(
                    &self.security,
                    req_id,
                    self.v3_msg_id.0,
                    names.clone(),
                    &mut self.send_pdu,
                )?;
                match self.send_and_recv_timeout(timeout).await {
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
            pdu::build_set(&self.security, req_id, req_id, names, &mut self.send_pdu)?;
            let recv_len = selfsend_and_recv_repeat(repeat, timeout).await?;
            self.req_id += Wrapping(1);
            let resp = self.getpdu(recv_len)?;
            if resp.message_type != SnmpMessageType::Response {
                return Err(SnmpError::AsnWrongType);
            }
            if resp.req_id != req_id {
                return Err(SnmpError::RequestIdMismatch);
            }
            /*
            if resp.community != &self.community[..] {
                return Err(SnmpError::CommunityMismatch);
            }
            */
            Ok(resp)
        }
    }
}
