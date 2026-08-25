use std::{collections::BTreeSet, fmt, io, path::Path};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs::File;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Read as _;

use minijinja::{AutoEscape, Environment, UndefinedBehavior};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};

use crate::{EmailError, EmailLimits, TemplateConfig, TemplateContext, TemplateName};

const FIXED_RECURSION_LIMIT: usize = 64;

/// Strictly rendered plain-text and HTML alternatives, exposed only by the explicit preview API.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedEmail {
    text: String,
    html: String,
}

impl RenderedEmail {
    /// Rendered plain-text alternative.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Rendered HTML alternative.
    #[must_use]
    pub fn html(&self) -> &str {
        &self.html
    }

    pub(crate) fn into_parts(self) -> (String, String) {
        (self.text, self.html)
    }
}

impl fmt::Debug for RenderedEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedEmail")
            .field("text", &"[REDACTED]")
            .field("html", &"[REDACTED]")
            .field("text_bytes", &self.text.len())
            .field("html_bytes", &self.html.len())
            .finish_non_exhaustive()
    }
}

/// Deterministic lint result for one successfully compiled text/HTML pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateLintEntry {
    template: TemplateName,
    variables: Vec<String>,
}

impl TemplateLintEntry {
    /// Registered path-free base name.
    #[must_use]
    pub const fn template(&self) -> &TemplateName {
        &self.template
    }

    /// Sorted undeclared variable paths referenced by either alternative.
    #[must_use]
    pub fn variables(&self) -> &[String] {
        &self.variables
    }
}

/// Deterministically ordered report proving every registered pair compiled under strict settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateLintReport {
    entries: Vec<TemplateLintEntry>,
}

impl TemplateLintReport {
    /// Lint entries in configured registry order.
    #[must_use]
    pub fn entries(&self) -> &[TemplateLintEntry] {
        &self.entries
    }

    /// Number of successfully compiled pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no template pairs were registered. Valid registries are never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Immutable trusted template registry with no filesystem loader or runtime path selection.
#[derive(Clone)]
pub struct TemplateRegistry {
    environment: Environment<'static>,
    registered: Vec<TemplateName>,
    limits: EmailLimits,
    lint: TemplateLintReport,
}

impl TemplateRegistry {
    /// Opens and loads every explicitly allowed text/HTML pair through retained descriptors.
    ///
    /// Files must be regular files opened relative to the trusted directory descriptor with
    /// `NOFOLLOW`. Both alternatives are read through a bounded reader and compiled before this
    /// function succeeds.
    ///
    /// # Errors
    ///
    /// Returns a stable value-free error for unsafe paths, missing pairs, oversized or non-UTF-8
    /// sources, or `MiniJinja` compilation failures.
    pub fn load(config: &TemplateConfig, limits: EmailLimits) -> Result<Self, EmailError> {
        limits.validate()?;
        config.validate(&limits)?;
        let root = open_trusted_template_directory(&config.directory)?;

        let mut environment = Environment::new();
        environment.set_undefined_behavior(UndefinedBehavior::Strict);
        environment.set_auto_escape_callback(|name| {
            if name
                .rsplit_once('.')
                .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("html"))
            {
                AutoEscape::Html
            } else {
                AutoEscape::None
            }
        });
        environment.set_fuel(Some(limits.render_fuel));
        environment.set_recursion_limit(FIXED_RECURSION_LIMIT);
        environment.set_keep_trailing_newline(true);

        let max_template_source_bytes =
            usize::try_from(limits.max_template_source_bytes).map_err(|_| EmailError::Config)?;
        for base in &config.allowed_templates {
            for extension in ["txt", "html"] {
                let registry_name = format!("{}.{}", base.as_str(), extension);
                let source =
                    read_trusted_template(&root, &registry_name, max_template_source_bytes)?;
                environment
                    .add_template_owned(registry_name, source)
                    .map_err(|_| EmailError::TemplateRegistry)?;
            }
        }

        let lint = build_lint_report(&environment, &config.allowed_templates)?;
        Ok(Self {
            environment,
            registered: config.allowed_templates.clone(),
            limits,
            lint,
        })
    }

    /// Renders one registered pair under strict undefined, fuel, and output-byte limits.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError::TemplateNotFound`] for an unregistered key, a strict value-free render
    /// failure, or [`EmailError::RenderLimit`] when either bounded writer fills.
    pub fn preview(
        &self,
        template: &TemplateName,
        context: &TemplateContext,
    ) -> Result<RenderedEmail, EmailError> {
        if !self.registered.contains(template) {
            return Err(EmailError::TemplateNotFound);
        }
        let max_context_bytes =
            usize::try_from(self.limits.max_context_bytes).map_err(|_| EmailError::Config)?;
        if context.serialized_bytes() > max_context_bytes {
            return Err(EmailError::ContextLimit);
        }
        let max_text_bytes =
            usize::try_from(self.limits.max_rendered_text_bytes).map_err(|_| EmailError::Config)?;
        let text = self.render_one(
            &format!("{}.txt", template.as_str()),
            context,
            max_text_bytes,
        )?;
        let max_html_bytes =
            usize::try_from(self.limits.max_rendered_html_bytes).map_err(|_| EmailError::Config)?;
        let html = self.render_one(
            &format!("{}.html", template.as_str()),
            context,
            max_html_bytes,
        )?;
        Ok(RenderedEmail { text, html })
    }

    /// Returns the deterministic compile-time lint report without re-reading template files.
    #[must_use]
    pub const fn lint(&self) -> &TemplateLintReport {
        &self.lint
    }

    fn render_one(
        &self,
        name: &str,
        context: &TemplateContext,
        maximum: usize,
    ) -> Result<String, EmailError> {
        let template = self
            .environment
            .get_template(name)
            .map_err(|_| EmailError::TemplateNotFound)?;
        let mut output = BoundedOutput::new(maximum);
        let result = template.render_captured_to(context.value(), &mut output);
        if output.exceeded {
            return Err(EmailError::RenderLimit);
        }
        result.map_err(|_| EmailError::TemplateRender)?;
        String::from_utf8(output.bytes).map_err(|_| EmailError::TemplateRender)
    }
}

impl fmt::Debug for TemplateRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TemplateRegistry")
            .field("template_count", &self.registered.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct TrustedTemplateDirectory(File);

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct TrustedTemplateDirectory;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_trusted_template_directory(path: &Path) -> Result<TrustedTemplateDirectory, EmailError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| EmailError::TemplateRegistry)?;
    let file = File::from(descriptor);
    let stat = fstat(&file).map_err(|_| EmailError::TemplateRegistry)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(EmailError::TemplateRegistry);
    }
    Ok(TrustedTemplateDirectory(file))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_trusted_template_directory(_path: &Path) -> Result<TrustedTemplateDirectory, EmailError> {
    Err(EmailError::TemplateRegistry)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_trusted_template(
    directory: &TrustedTemplateDirectory,
    relative: &str,
    maximum: usize,
) -> Result<String, EmailError> {
    let descriptor = openat(
        &directory.0,
        relative,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| EmailError::TemplateRegistry)?;
    let file = File::from(descriptor);
    let stat = fstat(&file).map_err(|_| EmailError::TemplateRegistry)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(EmailError::TemplateRegistry);
    }
    let file_len = usize::try_from(stat.st_size).map_err(|_| EmailError::TemplateRegistry)?;
    if file_len > maximum {
        return Err(EmailError::TemplateRegistry);
    }
    let take_limit = u64::try_from(maximum)
        .map_err(|_| EmailError::TemplateRegistry)?
        .checked_add(1)
        .ok_or(EmailError::TemplateRegistry)?;
    let mut reader = file.take(take_limit);
    let mut source = String::with_capacity(file_len);
    reader
        .read_to_string(&mut source)
        .map_err(|_| EmailError::TemplateRegistry)?;
    if source.len() > maximum {
        return Err(EmailError::TemplateRegistry);
    }
    Ok(source)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_trusted_template(
    _directory: &TrustedTemplateDirectory,
    _relative: &str,
    _maximum: usize,
) -> Result<String, EmailError> {
    Err(EmailError::TemplateRegistry)
}

fn build_lint_report(
    environment: &Environment<'static>,
    templates: &[TemplateName],
) -> Result<TemplateLintReport, EmailError> {
    let mut entries = Vec::with_capacity(templates.len());
    for template in templates {
        let mut variables = BTreeSet::new();
        for extension in ["txt", "html"] {
            let compiled = environment
                .get_template(&format!("{}.{}", template.as_str(), extension))
                .map_err(|_| EmailError::TemplateRegistry)?;
            variables.extend(compiled.undeclared_variables(true));
        }
        entries.push(TemplateLintEntry {
            template: template.clone(),
            variables: variables.into_iter().collect(),
        });
    }
    Ok(TemplateLintReport { entries })
}

struct BoundedOutput {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl BoundedOutput {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(8 * 1024)),
            maximum,
            exceeded: false,
        }
    }
}

impl io::Write for BoundedOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("render output limit"))?;
        if next > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("render output limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
