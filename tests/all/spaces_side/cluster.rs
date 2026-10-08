//! Cluster pieces for the phase 2 tests. An account lives on the node that
//! created it (`mint_plc_did` re-signs until the DID lands in a local
//! shard), so tests place accounts by picking the node they create them on.
//! Peers resolve each other's accounts (delegation tokens, service auth,
//! notifies) through one PLC directory, as a real cluster does.

use super::hooks::Front;
use crate::common::spaces::SpaceClient;
use crate::common::*;
use std::sync::Arc;

pub struct Plc {
    pub url: String,
    rotation: Arc<vlatproto::crypto::Keypair>,
}

impl Plc {
    pub async fn start() -> Plc {
        let plc = vlpds::plc::mock::MockPlc::start().await;
        Plc { url: plc.url, rotation: Arc::new(vlatproto::crypto::Keypair::generate()) }
    }

    /// Every node of a cluster registers under the same rotation key.
    pub fn apply(&self, c: &mut vlpds::server::Config) {
        use_plc(c, self.url.clone(), self.rotation.clone());
    }
}

/// A [`cluster_node`] with `--spaces` on, on `plc`.
pub async fn node(id: &str, bucket: &Arc<object_store::memory::InMemory>, shards: u32, plc: &Plc) -> TestServer {
    cluster_node(id, bucket.clone(), shards, |c| {
        plc.apply(c);
        c.spaces = true;
    })
    .await
}

/// A [`node`] whose public URL is `front`'s. OAuth tokens and DPoP proofs
/// name the public URL, so in a real cluster they hold on every node; a
/// client stays signed in when its account's shard moves elsewhere.
pub async fn fronted_node(
    id: &str,
    bucket: &Arc<object_store::memory::InMemory>,
    shards: u32,
    plc: &Plc,
    front: &Front,
) -> TestServer {
    let public = front.url.clone();
    cluster_node(id, bucket.clone(), shards, |c| {
        plc.apply(c);
        c.spaces = true;
        c.public_url = public;
    })
    .await
}

/// A space client whose account lives on `n` (created through the front
/// while it points there).
pub async fn client_on(front: &Front, n: &TestServer, prefix: &str, scope: &str) -> SpaceClient {
    front.point(n);
    SpaceClient::new(&front.view(n), &unique_name(prefix), scope).await
}

/// Points the front at `n` for good, and `clients` at its app.
pub fn settle_front(front: &Front, n: &TestServer, clients: &mut [&mut SpaceClient]) {
    front.point(n);
    for c in clients {
        c.srv.app = n.app.clone();
    }
}
