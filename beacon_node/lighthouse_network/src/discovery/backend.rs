//! ENR ownership without constructing a discovery server in the static-topology simulator.

use crate::Enr;
use discv5::Discv5;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;

pub(super) enum DiscoveryBackend {
    Discv5(Discv5),
    #[cfg(madsim)]
    Local {
        enr: Arc<RwLock<Enr>>,
        key: enr::CombinedKey,
    },
}

impl DiscoveryBackend {
    pub(super) fn server(&self) -> Option<&Discv5> {
        match self {
            Self::Discv5(server) => Some(server),
            #[cfg(madsim)]
            Self::Local { .. } => None,
        }
    }

    pub(super) fn local_enr(&self) -> Enr {
        match self {
            Self::Discv5(server) => server.local_enr(),
            #[cfg(madsim)]
            Self::Local { enr, .. } => enr.read().clone(),
        }
    }

    pub(super) fn external_enr(&self) -> Arc<RwLock<Enr>> {
        match self {
            Self::Discv5(server) => server.external_enr(),
            #[cfg(madsim)]
            Self::Local { enr, .. } => enr.clone(),
        }
    }

    pub(super) fn enr_insert<T: alloy_rlp::Encodable>(
        &self,
        field: &str,
        value: &T,
    ) -> Result<Option<Vec<u8>>, enr::Error> {
        match self {
            Self::Discv5(server) => server.enr_insert(field, value),
            #[cfg(madsim)]
            Self::Local { enr, key } => enr
                .write()
                .insert(field, value, key)
                .map(|old| old.map(|bytes| bytes.to_vec())),
        }
    }

    pub(super) fn update_local_enr_socket(&self, socket: SocketAddr, tcp: bool) -> bool {
        match self {
            Self::Discv5(server) => server.update_local_enr_socket(socket, tcp),
            #[cfg(madsim)]
            Self::Local { enr, key } => {
                let mut enr = enr.write();
                let current = match (tcp, socket) {
                    (true, SocketAddr::V4(_)) => enr.tcp4_socket().map(SocketAddr::V4),
                    (true, SocketAddr::V6(_)) => enr.tcp6_socket().map(SocketAddr::V6),
                    (false, SocketAddr::V4(_)) => enr.udp4_socket().map(SocketAddr::V4),
                    (false, SocketAddr::V6(_)) => enr.udp6_socket().map(SocketAddr::V6),
                };
                if current == Some(socket) {
                    return false;
                }
                if tcp {
                    enr.set_tcp_socket(socket, key).is_ok()
                } else {
                    enr.set_udp_socket(socket, key).is_ok()
                }
            }
        }
    }
}
