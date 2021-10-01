use std::net::SocketAddr;
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
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
const BUFFER_SIZE: usize = 4096;

pub struct SNMPSession {
    socket: Arc<UdpSocket>,
    pub community: Vec<u8>,
    pub req_id: Wrapping<i32>,
    pub version: i32,
    pub host: SocketAddr,
    rx: Receiver<Vec<u8>>,
    send_pdu: pdu::Buf,
    recv_buf: Vec<u8>,
}
impl SNMPSession {
    async fn send_and_recv(&mut self) -> SnmpResult<usize> {
        eprintln!("send_and_recv {:?}", self.host);
        let _sent_bytes = match self.socket.send(&self.send_pdu[..]).await {
            Err(e) => {
                eprintln!("Send error: {}", e);
                return Err(SnmpError::SendError(format!("{}", e).to_string()));
            }
            Ok(sendres) => sendres,
        };
        match self.rx.recv().await {
            None => {
                eprintln!("Received None");
                return Err(SnmpError::ReceiveError("Received None".to_string()));
            }
            Some(pdubuf) => {
                self.recv_buf.resize(pdubuf.len(), 0);
                self.recv_buf.copy_from_slice(&pdubuf[..]);
                return Ok(pdubuf.len());
            }
        }
    }
    async fn send_and_recv_timeout(&mut self, timeout: Duration) -> SnmpResult<usize> {
        match time::timeout(timeout, self.send_and_recv()).await {
            Err(_) => {
                return Err(SnmpError::Timeout);
            }
            Ok(resio) => resio,
        }
    }
    async fn send_and_recv_repeat(&mut self, repeat: u32, timeout: Duration) -> SnmpResult<usize> {
        for _ in 1..repeat {
            match self.send_and_recv_timeout(timeout).await {
                Err(e) => match e {
                    SnmpError::Timeout => continue,
                    other => return Err(other),
                },
                Ok(result) => return Ok(result),
            }
        }
        self.send_and_recv_timeout(timeout).await
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
        self.send_and_recv_repeat(repeat, timeout).await?;
        self.req_id += Wrapping(1);
        let resp = SnmpPdu::from_bytes(&self.recv_buf[..])?;
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
        self.send_and_recv_repeat(repeat, timeout).await?;
        self.req_id += Wrapping(1);
        let resp = SnmpPdu::from_bytes(&self.recv_buf[..])?;
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
        self.send_and_recv_repeat(repeat, timeout).await?;
        self.req_id += Wrapping(1);
        let resp = SnmpPdu::from_bytes(&self.recv_buf[..])?;
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
        self.send_and_recv_repeat(repeat, timeout).await?;
        self.req_id += Wrapping(1);
        let resp = SnmpPdu::from_bytes(&self.recv_buf[..])?;
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
    pub async fn get_oid(
        &mut self,
        oid: &str,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SnmpPdu<'_>> {
        self.get(get_oid_array(oid).as_slice(), repeat, timeout)
            .await
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
}
/// Asynchronous SNMP client for Tokio , so that it can work with actix
pub struct SNMPSocket {
    socket: Arc<UdpSocket>,
    recv_buf: [u8; BUFFER_SIZE],
    sessions: BTreeMap<IpAddr, Sender<Vec<u8>>>,
}

impl SNMPSocket {
    pub async fn new() -> std::io::Result<Self> {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::new(0, 0, 0, 0), 0)).await?;
        Ok(Self {
            socket: Arc::new(socket),
            recv_buf: [0; 4096],
            sessions: BTreeMap::new(),
        })
    }
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            recv_buf: [0; 4096],
            sessions: BTreeMap::new(),
        }
    }
    pub async fn session<SA: ToSocketAddrs>(
        &mut self,
        hostaddr: SA,
        community: &[u8],
        starting_req_id: i32,
        version: i32,
    ) -> std::io::Result<SNMPSession> {
        let socketaddr = match lookup_host(&hostaddr).await?.next() {
            //TODO find compat address
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "Lookup",
                ))
            }
            Some(a) => a,
        };
        let (tx, rx) = channel(100);
        self.sessions.insert(socketaddr.ip(), tx);
        Ok(SNMPSession {
            socket: self.socket.clone(),
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            version,
            host: socketaddr,
            rx,
            send_pdu: pdu::Buf::default(),
            recv_buf: Vec::new(),
        })
    }
    pub async fn run(&mut self, cancel: CancellationToken) {
        eprintln!("SNMPSocket run started");
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    // The token was cancelled
                    break;
                }
                i = self.recv_one() => {
                    match i {
                        Err(_) => break,
                        Ok(_) => {}
                    }
                }
            }
        }
        eprintln!("SNMPSocket run done");
    }
    async fn recv_one(&mut self) -> std::io::Result<()> {
        let (len, addr) = self.socket.recv_from(&mut self.recv_buf).await?;
        if let Some(tx) = self.sessions.get(&addr.ip()) {
            if let Err(e) = tx.try_send(self.recv_buf[0..len].to_vec()) {
                eprintln!("SNMP error pass response to {}: {}", addr, e);
            } else {
                return Ok(());
            }
        } else {
            println!("Unknown host {:?} - {} bytes received from", addr, len);
            return Ok(());
        }
        self.sessions.remove(&addr.ip());
        Ok(())
    }
}
