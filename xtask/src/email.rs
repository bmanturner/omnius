use std::{
    fs::{self, File},
    io::Read as _,
    path::Path,
};

use anyhow::{Context as _, Result, bail};
use omnius_email::{EmailLimits, TemplateConfig, TemplateContext, TemplateName, TemplateRegistry};

const MAX_CONTEXT_FILE_BYTES: usize = 128 * 1024;

pub fn lint(template_root: &Path, template_name: &str) -> Result<()> {
    let (registry, _) = registry(template_root, template_name)?;
    let report = registry.lint();
    for entry in report.entries() {
        println!(
            "{}: {}",
            entry.template().as_str(),
            entry.variables().join(", ")
        );
    }
    Ok(())
}

pub fn preview(template_root: &Path, template_name: &str, context_path: &Path) -> Result<()> {
    let (registry, template) = registry(template_root, template_name)?;
    let context = read_context(context_path)?;
    let rendered = registry
        .preview(&template, &context)
        .context("email template preview failed")?;
    println!(
        "--- text ---\n{}\n--- html ---\n{}",
        rendered.text(),
        rendered.html()
    );
    Ok(())
}

fn registry(template_root: &Path, template_name: &str) -> Result<(TemplateRegistry, TemplateName)> {
    let directory =
        fs::canonicalize(template_root).context("email template root is unavailable")?;
    let template =
        TemplateName::try_from(template_name).context("email template name is invalid")?;
    let config = TemplateConfig {
        directory,
        allowed_templates: vec![template.clone()],
    };
    let registry = TemplateRegistry::load(&config, EmailLimits::default())
        .context("email template registry is invalid")?;
    Ok((registry, template))
}

fn read_context(path: &Path) -> Result<TemplateContext> {
    let metadata = fs::symlink_metadata(path).context("email preview context is unavailable")?;
    let maximum_u64 = u64::try_from(MAX_CONTEXT_FILE_BYTES).unwrap_or(u64::MAX);
    if !metadata.file_type().is_file() || metadata.len() > maximum_u64 {
        bail!("email preview context is invalid");
    }
    let capacity = usize::try_from(metadata.len())
        .unwrap_or(usize::MAX)
        .min(MAX_CONTEXT_FILE_BYTES);
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .context("email preview context is unavailable")?
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("email preview context is unavailable")?;
    if bytes.len() > MAX_CONTEXT_FILE_BYTES {
        bail!("email preview context is invalid");
    }
    serde_json::from_slice(&bytes).context("email preview context is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnius_test_support::CleanDirectory;

    fn error_message(result: Result<TemplateContext>) -> String {
        result
            .err()
            .map_or_else(String::new, |error| error.to_string())
    }

    #[test]
    fn read_context_accepts_a_json_object() -> Result<()> {
        let directory = CleanDirectory::new("xtask-email-context-ok")?;
        let path = directory.path().join("context.json");
        fs::write(&path, br#"{"name":"Ada"}"#)?;
        read_context(&path)?;
        Ok(())
    }

    #[test]
    fn read_context_rejects_files_over_the_size_ceiling() -> Result<()> {
        let directory = CleanDirectory::new("xtask-email-context-size")?;
        let path = directory.path().join("context.json");
        // Valid JSON, so only the size check can reject it.
        let document = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_CONTEXT_FILE_BYTES));
        fs::write(&path, document)?;
        assert_eq!(
            error_message(read_context(&path)),
            "email preview context is invalid"
        );
        Ok(())
    }

    #[test]
    fn read_context_rejects_non_files_and_malformed_json() -> Result<()> {
        let directory = CleanDirectory::new("xtask-email-context-bad")?;
        assert_eq!(
            error_message(read_context(directory.path())),
            "email preview context is invalid"
        );
        let path = directory.path().join("context.json");
        fs::write(&path, b"{not json")?;
        assert_eq!(
            error_message(read_context(&path)),
            "email preview context is invalid"
        );
        assert_eq!(
            error_message(read_context(&directory.path().join("missing.json"))),
            "email preview context is unavailable"
        );
        Ok(())
    }
}
