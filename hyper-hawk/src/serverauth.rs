use std::fmt;
use std::any::Any;
use std::str::FromStr;
use hyper::Result;
use hyper::header::{Authorization, Scheme, Header, HeaderFormat};
use std::ops::{Deref, DerefMut};

/// 'Server-Authorization' header, as indicated in the canonical Hawk implementation.
///
/// This header appears to behave identically to the standard `Authorization` header,
/// so its implementation defers to that one and it functions identically. It can support
/// any Hyper scheme, although it is typically only used with the HawkScheme.
#[derive(Clone, PartialEq, Debug)]
pub struct ServerAuthorization<S: Scheme>(pub S);

impl<S: Scheme> Deref for ServerAuthorization<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: Scheme> DerefMut for ServerAuthorization<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.0
    }
}

impl<S: Scheme + Any> Header for ServerAuthorization<S>
    where <S as FromStr>::Err: 'static
{
    fn header_name() -> &'static str {
        "Server-Authorization"
    }

    fn parse_header(raw: &[Vec<u8>]) -> Result<ServerAuthorization<S>> {
        // parse an Authorization header, then steal its S and re-package it
        let authz_res: Result<Authorization<S>> = Header::parse_header(raw);
        match authz_res {
            Ok(a) => Ok(ServerAuthorization(a.0)),
            Err(e) => Err(e),
        }
    }
}

impl<S: Scheme + Any> HeaderFormat for ServerAuthorization<S>
    where <S as FromStr>::Err: 'static
{
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // copied from hyper's src/header/common/authorization.rs
        if let Some(scheme) = <S as Scheme>::scheme() {
            try!(write!(f, "{} ", scheme))
        };
        self.0.fmt_scheme(f)
    }
}
