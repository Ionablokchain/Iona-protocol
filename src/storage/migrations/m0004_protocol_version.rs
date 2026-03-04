//! Migration v3 -> v4: Introduce `node_meta.json` with protocol version tracking.
//!
//! This migration creates the `node_meta.json` file if it doesn't exist,
//! recording the current protocol version, schema version, and node binary version.

use crate::storage::SchemaMeta;
use std::{fs, io, path::Path};

pub fn migrate(data_dir: &str, meta: &mut SchemaMeta) -> io::Result<()> {
    let timestamp = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };

    let meta_path = format!("{data_dir}/node_meta.json");
    if !Path::new(&meta_path).exists() {
        let node_meta = crate::storage::meta::NodeMeta::new_current();
        let out = serde_json::to_string_pretty(&node_meta)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let tmp = format!("{meta_path}.tmp");
        fs::write(&tmp, &out)?;
        fs::rename(&tmp, &meta_path)?;
    }

    meta.migration_log.push(format!(
        "[{timestamp}] v3 -> v4: node_meta.json created with protocol version tracking"
    ));

    Ok(())
}
