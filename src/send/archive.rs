use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use walkdir::WalkDir;
use zip::write::FileOptions;

pub struct TempArchive {
    path: PathBuf,
}

impl TempArchive {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempArchive {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.path) {
            tracing::warn!(path = %self.path.display(), error = %err, "failed to remove temp zip archive");
        }
    }
}

pub fn create_temp_zip_archive(inputs: &[PathBuf]) -> Result<TempArchive> {
    let mut entries = Vec::<(PathBuf, PathBuf)>::new();
    let mut names = HashSet::<PathBuf>::new();

    for input in inputs {
        if input.is_dir() {
            let root = input
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("dir")
                .to_string();
            for entry in WalkDir::new(input)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
            {
                let file_path = entry.path().to_path_buf();
                let rel = file_path
                    .strip_prefix(input)
                    .unwrap_or(file_path.as_path())
                    .to_path_buf();
                let wanted = Path::new(&root).join(rel);
                let archive_name = unique_archive_path(&wanted, &mut names);
                entries.push((file_path, archive_name));
            }
        } else {
            let wanted =
                PathBuf::from(input.file_name().and_then(|x| x.to_str()).unwrap_or("file"));
            let archive_name = unique_archive_path(&wanted, &mut names);
            entries.push((input.clone(), archive_name));
        }
    }

    if entries.is_empty() {
        anyhow::bail!("No files found for zip archive");
    }

    let archive_path = std::env::temp_dir().join(format!("dropt-{}.zip", Uuid::new_v4()));
    write_zip_archive(&archive_path, &entries)?;
    Ok(TempArchive { path: archive_path })
}

fn unique_archive_path(wanted: &Path, names: &mut HashSet<PathBuf>) -> PathBuf {
    if names.insert(wanted.to_path_buf()) {
        return wanted.to_path_buf();
    }

    let stem = wanted
        .file_stem()
        .and_then(|x| x.to_str())
        .unwrap_or("file");
    let ext = wanted.extension().and_then(|x| x.to_str());
    let parent = wanted.parent().map(|x| x.to_path_buf()).unwrap_or_default();

    let mut idx = 2usize;
    loop {
        let candidate_name = match ext {
            Some(ext) if !ext.is_empty() => format!("{}-{}.{}", stem, idx, ext),
            _ => format!("{}-{}", stem, idx),
        };
        let candidate = parent.join(candidate_name);
        if names.insert(candidate.clone()) {
            return candidate;
        }
        idx += 1;
    }
}

fn write_zip_archive(archive_path: &Path, entries: &[(PathBuf, PathBuf)]) -> Result<()> {
    let file = File::create(archive_path)
        .with_context(|| format!("Failed to create zip archive {}", archive_path.display()))?;
    let mut writer = zip::ZipWriter::new(file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for (source_path, archive_path) in entries {
        let mut source = File::open(source_path)
            .with_context(|| format!("Failed to open {}", source_path.display()))?;
        let entry_name = archive_path.to_string_lossy().replace('\\', "/");
        writer
            .start_file(entry_name, options)
            .with_context(|| format!("Failed to start zip entry {}", archive_path.display()))?;
        io::copy(&mut source, &mut writer)
            .with_context(|| format!("Failed to add {} to zip", source_path.display()))?;
    }

    writer.finish().context("Failed to finalize zip archive")?;
    Ok(())
}
