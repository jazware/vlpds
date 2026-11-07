//! Spaces phase 1 side lane: leak, durability and fuzz harnesses and the
//! sync micro-bench, which drive the space surface over XRPC (see
//! tests/all/common/spaces.rs), and the ported reference space suites
//! (`ref_*`, on the `ref_net` harness). Phase 2's cluster checks are the
//! `cluster_*` modules: split and merge with space rows, revocation across
//! nodes, the leak test across nodes and their peer streams, and takeover
//! mid-burst. Phase 3's: importRepo round trips and refusals
//! (`import_repo`), space repos in the account backup (`backup`), takedowns
//! on every read path (`takedowns`) and audited operator reads
//! (`operator_reads`), with their shared pieces in `phase3`.

mod accept;
mod applied_writes;
mod backup;
mod bench;
mod check;
mod cluster;
mod cluster_leak;
mod cluster_reshard;
mod cluster_revocation;
mod cluster_takeover;
mod durability;
mod fuzz;
mod hooks;
mod import_limits;
pub(crate) mod import_repo;
mod leak;
mod operator_reads;
mod phase3;
mod ref_client_attestation;
mod ref_net;
mod ref_space_auth;
mod ref_space_migration;
mod ref_space_policy;
mod ref_space_records;
mod ref_space_scope;
mod ref_space_sync;
mod space_deleted;
mod takedowns;
