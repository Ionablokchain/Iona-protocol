use std::{fs, io, path::PathBuf};

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PeerStoreFile {
    addrs: Vec<String>,
}

pub struct PeerStore {
    path: PathBuf,
    data: PeerStoreFile,
}

impl PeerStore {
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let data = if path.exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s).unwrap_or_default()
        } else {
            PeerStoreFile::default()
        };
        Ok(Self { path, data })
    }

    pub fn addrs(&self) -> Vec<String> {
        self.data.addrs.clone()
    }

    pub fn add(&mut self, addr: String) -> io::Result<()> {
        if !self.data.addrs.contains(&addr) {
            self.data.addrs.push(addr);
            self.persist()?;
        }
        Ok(())
    }

    fn persist(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let s = serde_json::to_string_pretty(&self.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("peer-store encode: {e}")))?;
        fs::write(&self.path, s)
    }
}
