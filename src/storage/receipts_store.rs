use crate::types::{Hash32, Receipt};
use std::fs;
use std::io;
use std::path::PathBuf;

pub struct ReceiptsStore {
    dir: PathBuf,
}

impl ReceiptsStore {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = root.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path_for(&self, id: &Hash32) -> PathBuf {
        self.dir.join(format!("{}.json", hex::encode(id.0)))
    }

    pub fn put(&self, id: &Hash32, receipts: &[Receipt]) -> io::Result<()> {
        let s = serde_json::to_string_pretty(receipts)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("receipt encode: {e}")))?;
        fs::write(self.path_for(id), s)
    }

    pub fn get(&self, id: &Hash32) -> io::Result<Option<Vec<Receipt>>> {
        let p = self.path_for(id);
        if !p.exists() {
            return Ok(None);
        }
        let s = fs::read_to_string(p)?;
        let r = serde_json::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("receipt decode: {e}")))?;
        Ok(Some(r))
    }
}
