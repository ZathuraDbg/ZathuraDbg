use std::{collections::HashMap, path::PathBuf};

pub trait Input {
    fn open(&mut self, name: &str) -> std::io::Result<String>;
}

pub struct FileLoader {
    root: PathBuf,
    cache: HashMap<String, String>,
}

impl FileLoader {
    pub fn new(root: PathBuf) -> Self {
        Self { root, cache: HashMap::new() }
    }

    pub fn open_file(&mut self, name: &str) -> std::io::Result<String> {
        if let Some(content) = self.cache.get(name) {
            return Ok(content.clone());
        }

        let content = std::fs::read_to_string(self.root.join(name))?;
        self.cache.insert(name.to_owned(), content.clone());
        Ok(content)
    }
}

impl Input for FileLoader {
    fn open(&mut self, name: &str) -> std::io::Result<String> {
        self.open_file(name)
    }
}

impl Input for HashMap<String, String> {
    fn open(&mut self, name: &str) -> std::io::Result<String> {
        let content = self.get(name).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "file not found".to_owned())
        })?;
        Ok(content.clone())
    }
}
