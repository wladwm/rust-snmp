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
//use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{RwLock,Mutex};
use tokio::time::{self, Duration};
const BUFFER_SIZE: usize = 4096;

pub struct SNMPSession {
    socket: Arc<UdpSocket>,
    community: Vec<u8>,
    req_id: Wrapping<i32>,
    version: i32,
    pub host: SocketAddr,
    rx: Receiver<Vec<u8>>,
    send_pdu: pdu::Buf,
    recv_buf: Vec<u8>,
}
impl SNMPSession {
    pub fn host(&self) -> &SocketAddr {
        &self.host
    }
    pub fn set_host(&mut self, new_host: SocketAddr) {
        self.host = new_host;
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
        if community.len() < 1 {
            return Err(SnmpError::CommunityMismatch);
        }
        self.community.resize(community.len(), 0);
        self.community.as_mut_slice().copy_from_slice(community);
        Ok(())
    }

    async fn send_and_recv(&mut self) -> SnmpResult<usize> {
        let _sent_bytes = match self.socket.send_to(&self.send_pdu[..], self.host).await {
            Err(e) => {
                return Err(SnmpError::SendError(format!("{}", e).to_string()));
            }
            Ok(sendres) => sendres,
        };
        match self.rx.recv().await {
            None => {
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
#[derive(Clone)]
struct SNMPSocketInner {
    socket: Arc<UdpSocket>,
    sessions: Arc<RwLock<BTreeMap<SocketAddr, Sender<Vec<u8>>>>>,
}
impl SNMPSocketInner {
    async fn new() -> std::io::Result<Self> {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::new(0, 0, 0, 0), 0)).await?;
        Ok(Self {
            socket: Arc::new(socket),
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }
    fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    async fn clear_closed_sessions(&self) -> usize {
        let mut grd=self.sessions.write().await;
        grd.retain(|_k, v| !v.is_closed());
        grd.len()
    }
    async fn run(&self) {
        self.clear_closed_sessions().await;
        let mut buf = Vec::<u8>::new();
        buf.resize(BUFFER_SIZE, 0);
        let mbuf = buf.as_mut_slice();
        loop {
            match self.recv_one(mbuf).await {
                Err(_) => break,
                Ok(_) => {}
            }
        }
        self.clear_closed_sessions().await;
    }
    async fn recv_one(&self, buf: &mut [u8]) -> std::io::Result<()> {
        let (len, addr) = self.socket.recv_from(buf).await?;
        if let Some(tx) = self.sessions.read().await.get(&addr) {
            if let Err(e) = tx.try_send(buf[0..len].to_vec()) {
                eprintln!("Warning: SNMP error pass response to {}: {}", addr, e);
                if self.clear_closed_sessions().await<1 {
                    //stop receive task
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                }
                return Ok(());
            } else {
                return Ok(());
            }
        } else {
            println!(
                "Warning: Unknown host {:?} - {} bytes received from",
                addr, len
            );
            return Ok(());
        }
    }
}
#[derive(Clone)]
pub struct SNMPSocket {
    inner: SNMPSocketInner,
    recv_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl SNMPSocket {
    pub async fn new() -> std::io::Result<Self> {
        Ok(Self {
            inner: SNMPSocketInner::new().await?,
            recv_task: Arc::new(Mutex::new(None))
        })
    }
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            inner: SNMPSocketInner::from_socket(socket),
            recv_task: Arc::new(Mutex::new(None))
        }
    }
    pub async fn session<SA: ToSocketAddrs>(
        &self,
        hostaddr: SA,
        community: &[u8],
        starting_req_id: i32,
        version: i32,
    ) -> std::io::Result<SNMPSession> {
        let la=self.inner.socket.local_addr()?;
        let socketaddr = match lookup_host(&hostaddr).await?.find(|a|{
            (a.is_ipv4() && la.is_ipv4()) || (a.is_ipv6() && la.is_ipv6())
        }) {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "Lookup",
                ))
            }
            Some(a) => a,
        };
        if let Some(sess) = self.inner.sessions.read().await.get(&socketaddr) {
            if !sess.is_closed() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "Session already exists",
                ));
            }
        }
        let (tx, rx) = channel(100);
        self.inner.sessions.write().await.insert(socketaddr.clone(), tx);
        {
            let mut rt_g=self.recv_task.lock().await;
            let inner = self.inner.clone();
            if rt_g.is_none() {
                *rt_g=Some(tokio::spawn(async move {
                    inner.run().await;
                    ()
                }));
            }
        }
        Ok(SNMPSession {
            socket: self.inner.socket.clone(),
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            version,
            host: socketaddr,
            rx,
            send_pdu: pdu::Buf::default(),
            recv_buf: Vec::new(),
        })
    }
}
