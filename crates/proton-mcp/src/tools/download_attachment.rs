//! `download_attachment` — download and decrypt one attachment to disk.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router, ErrorData};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::common::*;
use crate::server::ProtonMail;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DownloadAttachmentParams {
    /// Message id or free text identifying the message.
    pub message_ref: String,
    /// The attachment id (see `list_attachments`).
    pub attachment_id: String,
    /// Relative subdirectory under the server's attachment root. Defaults to '.'.
    #[serde(default = "default_dest")]
    pub dest_dir: String,
}

fn default_dest() -> String {
    ".".into()
}

fn confined_directory(root: &std::path::Path, dest: &str) -> std::io::Result<std::path::PathBuf> {
    use std::path::Component;
    let relative = std::path::Path::new(dest);
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "attachment directory must be relative and cannot contain '..'",
        ));
    }
    std::fs::create_dir_all(root)?;
    let root = root.canonicalize()?;
    let mut path = root.clone();
    for part in relative.components() {
        if let Component::Normal(part) = part {
            path.push(part);
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "symlink or non-directory in attachment path",
                    ))
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(&path)?,
                Err(e) => return Err(e),
            }
        }
    }
    let path = path.canonicalize()?;
    if !path.starts_with(&root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "attachment path escaped root",
        ));
    }
    Ok(path)
}

#[tool_router(router = download_attachment_router, vis = "pub(crate)")]
impl ProtonMail {
    #[tool(
        name = "download_attachment",
        description = "Download and decrypt one attachment, writing it into dest_dir. Returns the written file path."
    )]
    pub async fn download_attachment(
        &self,
        Parameters(p): Parameters<DownloadAttachmentParams>,
    ) -> Result<Out, ErrorData> {
        let root = std::env::var_os("PROTON_ATTACHMENT_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("attachments"));
        let dir = confined_directory(&root, &p.dest_dir)
            .map_err(|e| ErrorData::invalid_params(format!("attachment directory: {e}"), None))?;
        let mut guard = self.state.client.lock().await;
        self.ensure(&mut guard).await?;
        let client = guard.as_ref().expect("client present");

        let message_id = self.resolve(client, &p.message_ref).await?;
        let (filename, bytes) = client
            .download_attachment(&message_id, &p.attachment_id)
            .await
            .map_err(|e| self.map_err(e))?;

        // Use only the file name component to avoid path traversal from the server name.
        let safe_name = std::path::Path::new(&filename)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "attachment.bin".to_string());
        let path = dir.join(&safe_name);
        let written = bytes.len();
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&path)
            .and_then(|mut f| f.write_all(&bytes))
            .map_err(|e| ErrorData::internal_error(format!("write file: {e}"), None))?;

        Ok(obj(json!({
            "saved": true,
            "filename": safe_name,
            "path": path.to_string_lossy(),
            "bytes_written": written,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_absolute_parent_and_symlink_destinations() {
        let root = std::env::temp_dir().join(format!("attachment-test-{}", std::process::id()));
        assert!(confined_directory(&root, "../escape").is_err());
        assert!(confined_directory(&root, "/etc").is_err());
        let dir = confined_directory(&root, "invoices").unwrap();
        assert!(dir.starts_with(root.canonicalize().unwrap()));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/tmp", root.join("link")).unwrap();
            assert!(confined_directory(&root, "link").is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
