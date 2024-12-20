use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::Wrapping;
// use std::time::Duration;
// use tokio::prelude::*;
use crate::get_oid_array;
use crate::pdu;
use crate::SnmpError;
use crate::SnmpMessageType;
use crate::SnmpPdu;
use crate::SnmpResult;
use crate::Value;
use tokio::io;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};
//use std::fmt ;
use tokio::time::{self, Duration};
const BUFFER_SIZE: usize = 4096;

/// Asynchronous SNMP client for Tokio , so that it can work with actix
pub struct TokioSession {
    socket: UdpSocket,
    community: Vec<u8>,
    req_id: Wrapping<i32>,
    send_pdu: pdu::Buf,
    recv_buf: [u8; BUFFER_SIZE],
    version: i32,
}

impl TokioSession {
    pub async fn new<SA>(
        destination: SA,
        community: &[u8],
        starting_req_id: i32,
        version: i32,
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
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            send_pdu: pdu::Buf::default(),
            recv_buf: [0; BUFFER_SIZE],
            version,
        })
    }
    pub fn last_req_id(&self) -> i32 {
        self.req_id.0
    }
    pub fn set_last_req_id(&mut self, reqid: i32) {
        self.req_id.0 = reqid;
    }
    pub fn snmp_version(&self) -> i32 {
        self.version
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

    async fn send_and_recv(
        socket: &mut UdpSocket,
        pdu: &pdu::Buf,
        out: &mut [u8],
    ) -> SnmpResult<usize> {
        match socket.send(&pdu[..]).await {
            Ok(_pdu_len) => match socket.recv(out).await {
                Ok(len) => Ok(len),
                Err(e) => Err(SnmpError::ReceiveError(format!("{}", e))),
            },
            Err(e) => Err(SnmpError::SendError(format!("{}", e))),
        }
    }

    async fn send_and_recv_repeat(
        socket: &mut UdpSocket,
        pdu: &pdu::Buf,
        out: &mut [u8],
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<usize> {
        for _ in 1..repeat {
            match time::timeout(timeout, Self::send_and_recv(socket, pdu, out)).await {
                Err(_) => {}
                Ok(result) => {
                    if let Ok(len) = result {
                        return Ok(len);
                    }
                }
            }
        }
        match time::timeout(timeout, Self::send_and_recv(socket, pdu, out)).await {
            Err(_) => Err(SnmpError::Timeout),
            Ok(result) => result,
        }
    }

    pub async fn get_oid(
        &mut self,
        oid: &str,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>> {
        self.get(get_oid_array(oid).as_slice(), repeat, timeout)
            .await
    }

    pub async fn get(
        &mut self,
        name: &[u32],
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>> {
        let req_id = self.req_id.0;
        pdu::build_get(
            self.community.as_slice(),
            req_id,
            name,
            &mut self.send_pdu,
            self.version,
        );
        let recv_len = Self::send_and_recv_repeat(
            &mut self.socket,
            &self.send_pdu,
            &mut self.recv_buf[..],
            repeat,
            timeout,
        )
        .await?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }
    pub async fn getmulti(
        &mut self,
        names: &[&[u32]],
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>> {
        let req_id = self.req_id.0;
        pdu::build_getmulti(
            self.community.as_slice(),
            req_id,
            names,
            &mut self.send_pdu,
            self.version,
        );
        let recv_len = Self::send_and_recv_repeat(
            &mut self.socket,
            &self.send_pdu,
            &mut self.recv_buf[..],
            repeat,
            timeout,
        )
        .await?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }
    pub async fn get_oid_next(
        &mut self,
        oid: &str,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>> {
        self.getnext(get_oid_array(oid).as_slice(), repeat, timeout)
            .await
    }
    pub async fn getnext(
        &mut self,
        name: &[u32],
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>> {
        let req_id = self.req_id.0;
        pdu::build_getnext(
            self.community.as_slice(),
            req_id,
            name,
            &mut self.send_pdu,
            self.version,
        );
        let recv_len = Self::send_and_recv_repeat(
            &mut self.socket,
            &self.send_pdu,
            &mut self.recv_buf[..],
            repeat,
            timeout,
        )
        .await?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }

    pub async fn getbulk(
        &mut self,
        names: &[&[u32]],
        non_repeaters: u32,
        max_repetitions: u32,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>> {
        let req_id = self.req_id.0;
        pdu::build_getbulk(
            self.community.as_slice(),
            req_id,
            names,
            non_repeaters,
            max_repetitions,
            &mut self.send_pdu,
        );
        let recv_len = Self::send_and_recv_repeat(
            &mut self.socket,
            &self.send_pdu,
            &mut self.recv_buf[..],
            repeat,
            timeout,
        )
        .await?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
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
    pub async fn set(
        &mut self,
        values: &[(&[u32], Value<'_>)],
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>> {
        let req_id = self.req_id.0;
        pdu::build_set(
            self.community.as_slice(),
            req_id,
            values,
            &mut self.send_pdu,
            self.version,
        );
        let recv_len = Self::send_and_recv_repeat(
            &mut self.socket,
            &self.send_pdu,
            &mut self.recv_buf[..],
            repeat,
            timeout,
        )
        .await?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }
}
