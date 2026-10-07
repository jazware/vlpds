//! Object store handle. The optional injected latency on segment PUTs
//! emulates S3 Standard/Express against a local MinIO.

use object_store::aws::AmazonS3Builder;
use object_store::ObjectStore;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct Store {
    pub raw: Arc<dyn ObjectStore>,
    pub prefix: String,
    /// (median ms, lognormal sigma)
    pub latency: Option<(f64, f64)>,
}

#[derive(Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .field("region", &self.region)
            .finish()
    }
}

impl Store {
    /// Keeps up to `connections` idle (the in-flight bound of
    /// [`limited`](Self::limited)) so connections are reused: each close
    /// leaves a TIME_WAIT socket on an ephemeral port.
    pub fn s3(cfg: &S3Config, prefix: &str, latency: Option<(f64, f64)>, connections: usize) -> anyhow::Result<Store> {
        Self::s3_with(cfg, prefix, latency, connections, false)
    }

    /// [`Self::s3`], optionally sending bodies as `UNSIGNED-PAYLOAD`: SigV4
    /// otherwise hashes every PUT body in full on the calling task, which
    /// over TLS (where the connection already protects the body) is a pass
    /// over every byte for nothing.
    pub fn s3_with(
        cfg: &S3Config,
        prefix: &str,
        latency: Option<(f64, f64)>,
        connections: usize,
        unsigned_payload: bool,
    ) -> anyhow::Result<Store> {
        let s3 = Self::s3_builder(cfg, prefix, connections, unsigned_payload).build()?;
        Ok(Store { raw: Arc::new(s3), prefix: prefix.trim_end_matches('/').to_string(), latency })
    }

    /// The control plane's client: writes to node leases back off from a
    /// floor of min(1 s, `renew_every`) on throttling
    /// ([`crate::throttle::ctl_write_retry`]), everything else keeps the
    /// default schedule. Each half pools up to `connections`.
    pub fn s3_ctl(cfg: &S3Config, prefix: &str, connections: usize, renew_every: Duration) -> anyhow::Result<Store> {
        let plain = Self::s3_builder(cfg, prefix, connections, false).build()?;
        let lease = Self::s3_builder(cfg, prefix, connections, false)
            .with_retry(crate::throttle::ctl_write_retry(rand::random(), renew_every))
            .build()?;
        let prefix = prefix.trim_end_matches('/').to_string();
        let raw = Arc::new(crate::throttle::LeaseWrites {
            plain: Arc::new(plain),
            lease: Arc::new(lease),
            prefix: prefix.clone(),
        });
        Ok(Store { raw, prefix, latency: None })
    }

    fn s3_builder(cfg: &S3Config, prefix: &str, connections: usize, unsigned_payload: bool) -> AmazonS3Builder {
        AmazonS3Builder::new()
            .with_http_connector(crate::throttle::Counting::new(&cfg.bucket, prefix))
            .with_unsigned_payload(unsigned_payload)
            .with_endpoint(&cfg.endpoint)
            .with_bucket_name(&cfg.bucket)
            .with_access_key_id(&cfg.access_key)
            .with_secret_access_key(&cfg.secret_key)
            .with_region(&cfg.region)
            .with_virtual_hosted_style_request(false)
            .with_client_options(
                // h2 to S3 is slower and S3 caps streams per connection. S3
                // closes idle connections after ~20 s; dropping ours at 15 s
                // avoids reusing one the server is closing.
                object_store::ClientOptions::new()
                    .with_http1_only()
                    .with_pool_max_idle_per_host(connections.max(1))
                    .with_pool_idle_timeout(Duration::from_secs(15))
                    .with_connect_timeout(Duration::from_secs(2))
                    .with_timeout(Duration::from_secs(30))
                    // must be set after with_client_options would overwrite it
                    .with_allow_http(cfg.endpoint.starts_with("http://")),
            )
    }

    pub fn memory(latency: Option<(f64, f64)>) -> Store {
        Store { raw: Arc::new(object_store::memory::InMemory::new()), prefix: "vlpds".into(), latency }
    }

    /// Wrap each underlying client once.
    pub fn counted(self, client: &'static str) -> Store {
        Store { raw: crate::objstats::counted(self.raw, &self.prefix, client), ..self }
    }

    /// [`Store::counted`], also keeping the node's object counts.
    pub fn counted_into(self, client: &'static str, stats: &Arc<crate::store_stats::StoreStats>) -> Store {
        Store { raw: crate::objstats::counted_with(self.raw, &self.prefix, client, Some(stats.clone())), ..self }
    }

    /// Wrap each underlying client once, after `counted`, so the request
    /// metrics time the wire, not the wait for a permit.
    pub fn limited(self, client: &'static str, limits: crate::objlimit::Limits) -> Store {
        Store { raw: crate::objlimit::limited(self.raw, &self.prefix, client, limits), ..self }
    }

    pub async fn inject_latency(&self) {
        if let Some((median, sigma)) = self.latency {
            // Box-Muller
            let u1: f64 = rand::random::<f64>().max(1e-12);
            let u2: f64 = rand::random();
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            let d = Duration::from_secs_f64(median * (sigma * z).exp() / 1000.0);
            // tokio's timer rounds up to whole milliseconds, which would
            // turn a sub-ms PUT (MinIO, a same-zone S3 Express) into 1-2 ms
            if d < Duration::from_millis(5) {
                let _ = tokio::task::spawn_blocking(move || std::thread::sleep(d)).await;
            } else {
                tokio::time::sleep(d).await;
            }
        }
    }
}
