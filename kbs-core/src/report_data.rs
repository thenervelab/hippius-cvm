//! SNP `REPORT_DATA` layouts (ARCHITECTURE.md §20) — canonical
//! definitions live in `hippius_types::report_data`. Re-exported here
//! for backwards compatibility with internal kbs-core call sites.

pub use hippius_types::report_data::{audit_vm, ct_eq, tenant, AUDIT_VM_DOMAIN, REPORT_DATA_LEN};
