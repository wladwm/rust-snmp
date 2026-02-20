use crate::tokio_socket::*;
use crate::*;
use futures_util::future::{BoxFuture, FutureExt};
use futures_util::stream::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct SnmpWalkParams {
    pub tries: u32,
    pub bulk: u32,
    pub timeout: Duration,
}
impl Default for SnmpWalkParams {
    fn default() -> SnmpWalkParams {
        SnmpWalkParams {
            tries: 1,
            bulk: 0,
            timeout: Duration::from_secs(10),
        }
    }
}
impl SnmpWalkParams {
    pub fn new(tries: u32, bulk: u32, timeout: Duration) -> SnmpWalkParams {
        SnmpWalkParams {
            tries,
            bulk,
            timeout,
        }
    }
}
struct SnmpWalkInner<'a, 'b> {
    sess: &'a mut SNMPSession,
    params: SnmpWalkParams,
    walkoid: &'b [u32],
    reqnext: Vec<u32>,
}
impl<'a, 'b> SnmpWalkInner<'a, 'b> {
    fn new(sess: &'a mut SNMPSession, params: SnmpWalkParams, walkoid: &'b [u32]) -> Self {
        SnmpWalkInner {
            sess,
            params,
            walkoid,
            reqnext: walkoid.to_vec(),
        }
    }
    async fn getnext(self) -> Result<(SnmpOwnedPdu, SnmpWalkInner<'a, 'b>), SnmpError> {
        let rsp = match if self.params.bulk > 1 {
            self.sess
                .getbulk::<&[u32], &[u32], _>(
                    [&self.reqnext[..]],
                    0,
                    self.params.bulk,
                    self.params.tries,
                    self.params.timeout,
                )
                .await
        } else {
            self.sess
                .getnext::<&[u32], &[u32]>(
                    &self.reqnext.as_slice(),
                    self.params.tries,
                    self.params.timeout,
                )
                .await
        } {
            Err(e) => return Err(e),
            Ok(r) => r,
        };
        Ok((rsp, self))
    }
}
impl<'a, 'b> Unpin for SnmpWalkInner<'a, 'b> {}
unsafe impl<'a, 'b> Send for SnmpWalkInner<'a, 'b> {}

#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct SnmpWalk<'a: 'c, 'b: 'c, 'c, F, T>
where
    F: Fn(ObjectIdentifier, Value, &SnmpOwnedPdu) -> Option<T>,
{
    inner: Option<SnmpWalkInner<'a, 'b>>,
    rsp: Option<SnmpOwnedPdu>,
    pos: usize,
    futget: Option<BoxFuture<'c, Result<(SnmpOwnedPdu, SnmpWalkInner<'a, 'b>), SnmpError>>>,
    func: F,
}
impl<'a, 'b, 'c, F, T> Unpin for SnmpWalk<'a, 'b, 'c, F, T> where
    F: Fn(ObjectIdentifier, Value, &SnmpOwnedPdu) -> Option<T>
{
}
unsafe impl<'a, 'b, 'c, F, T> Send for SnmpWalk<'a, 'b, 'c, F, T> where
    F: Fn(ObjectIdentifier, Value, &SnmpOwnedPdu) -> Option<T>
{
}
impl<'a: 'c, 'b: 'c, 'c, F, T> SnmpWalk<'a, 'b, 'c, F, T>
where
    F: Fn(ObjectIdentifier, Value, &SnmpOwnedPdu) -> Option<T>,
{
    pub fn new(
        sess: &'a mut SNMPSession,
        params: SnmpWalkParams,
        walkoid: &'b [u32],
        func: F,
    ) -> Self {
        SnmpWalk {
            inner: Some(SnmpWalkInner::new(sess, params, walkoid)),
            rsp: None,
            pos: 0,
            futget: None,
            func,
        }
    }
    fn get_session_name(&self) -> Option<String> {
        self.inner.as_ref().map(|x| x.sess.host.to_string())
    }
}
impl<'a: 'c, 'b: 'c, 'c, F, T> Stream for SnmpWalk<'a, 'b, 'c, F, T>
where
    F: Fn(ObjectIdentifier, Value, &SnmpOwnedPdu) -> Option<T>,
{
    type Item = Result<T, SnmpError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let need_restart_no_bulk = match self.rsp.as_ref() {
                None => false,
                Some(rsp) => {
                    if rsp.error_status != 0 {
                        if let Some(inr) = self.inner.as_ref() {
                            trace!(
                                "SnmpWalk {} need_restart_no_bulk check error_status {}",
                                self.get_session_name().unwrap_or_default(),
                                rsp.error_status
                            );
                            inr.params.bulk > 0
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
            };
            if need_restart_no_bulk {
                let sessname = self.get_session_name().unwrap_or_default();
                if let Some(inr) = self.inner.as_mut() {
                    trace!("SnmpWalk {} switch off bulk {}", sessname, inr.params.bulk);
                    inr.params.bulk = 0
                }
                let _ = self.rsp.take(); //ignore error response for first time
                continue;
            }
            let bulk = self.inner.as_ref().map(|inr| inr.params.bulk).unwrap_or(0);
            let q = match self.rsp.as_ref() {
                None => None,
                Some(rsp) => {
                    trace!(
                        "SnmpWalk adv {} error_status {} bulk {}",
                        self.get_session_name().unwrap_or_default(),
                        rsp.error_status,
                        bulk
                    );
                    let mut vars = rsp.varbinds();
                    vars.advance(self.pos);
                    match vars.next() {
                        None => None,
                        Some(q) => {
                            let mut oidname: ObjIdBuf = [0u32; 128];
                            let nm = match q.0.read_name(&mut oidname) {
                                Ok(n) => n,
                                Err(e) => {
                                    warn!(
                                        "SnmpWalk {} read_name error {}",
                                        self.get_session_name().unwrap_or_default(),
                                        e
                                    );
                                    continue;
                                }
                            };
                            let walkoid = self.inner.as_ref().unwrap().walkoid;
                            if nm.len() < walkoid.len() {
                                trace!(
                                    "SnmpWalk {} name len {}<{}",
                                    self.get_session_name().unwrap_or_default(),
                                    nm.len(),
                                    walkoid.len()
                                );
                                return Poll::Ready(None);
                            }
                            if !nm[0..walkoid.len()].eq(walkoid) {
                                trace!(
                                    "SnmpWalk {} name {:?} does not match {:?}",
                                    self.get_session_name().unwrap_or_default(),
                                    nm,
                                    walkoid
                                );
                                return Poll::Ready(None);
                            }
                            Some(((self.func)(q.0, q.1, rsp), nm.to_vec(), vars.pos()))
                        }
                    }
                }
            };
            if let Some(q) = q {
                self.pos = q.2;
                self.inner.as_mut().unwrap().reqnext = q.1;
                match q.0 {
                    None => return Poll::Ready(None),
                    Some(v) => return Poll::Ready(Some(Ok(v))),
                }
            };
            let mut futget = match self.futget.take() {
                Some(f) => f,
                None => match self.inner.take() {
                    None => return Poll::Ready(None),
                    Some(inner) => inner.getnext().boxed(),
                },
            };
            let r = match futget.poll_unpin(cx) {
                Poll::Pending => {
                    self.futget = Some(futget);
                    return Poll::Pending;
                }
                Poll::Ready(r) => match r {
                    Err(e) => return Poll::Ready(Some(Err(e))),
                    Ok(r) => r,
                },
            };
            let bulk = self.inner.as_ref().map(|inr| inr.params.bulk).unwrap_or(0);
            trace!(
                "SnmpWalk got {} error_status {} bulk {}",
                r.1.sess.host.to_string(),
                r.0.error_status,
                bulk
            );
            if r.0.error_status != 0 && bulk > 0 {
                trace!("SnmpWalk {} switch off bulk", r.1.sess.host.to_string());
                if let Some(inr) = self.inner.as_mut() {
                    inr.params.bulk = 0;
                }
                continue;
            }
            let mut vars = r.0.varbinds();
            let fv = match vars.next() {
                None => return Poll::Ready(None), //empty response
                Some(v) => v,
            };
            let mut oidname: ObjIdBuf = [0u32; 128];
            let nm = match fv.0.read_name(&mut oidname) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Some(Err(e))), //invalid response
            };
            if nm.len() < r.1.walkoid.len() {
                trace!(
                    "SnmpWalk {} name len {}<{}",
                    r.1.sess.host.to_string(),
                    nm.len(),
                    r.1.walkoid.len()
                );
                return Poll::Ready(None);
            }
            if nm.eq(r.1.walkoid) {
                warn!(
                    "SnmpWalk {} response {:?} OID {:?} is not increasing",
                    r.1.sess.host.to_string(),
                    fv,
                    nm
                );
                return Poll::Ready(Some(Err(SnmpError::OidIsNotIncreasing)));
            };
            if !r.1.walkoid.eq(&nm[0..r.1.walkoid.len()]) {
                // walk finished
                trace!(
                    "SnmpWalk {} response {:?} walk finished for {:?}",
                    r.1.sess.host.to_string(),
                    fv,
                    r.1.walkoid
                );
                return Poll::Ready(None);
            }
            self.rsp = Some(r.0);
            self.pos = 0;
            self.inner = Some(r.1);
        }
    }
}
