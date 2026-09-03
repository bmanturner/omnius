//! Hygienic application-migration embedding for `omnius-service-kit` consumers.

use proc_macro::TokenStream;

use proc_macro_crate::{FoundCrate, crate_name};
use quote::quote;
use syn::{LitStr, Path, parse_quote, visit_mut::VisitMut};

/// Embeds migrations while resolving `SQLx` types through the consumer's
/// `omnius-service-kit` dependency, regardless of that dependency's alias.
#[proc_macro]
pub fn migrate(input: TokenStream) -> TokenStream {
    match expand(input) {
        Ok(output) => output,
        Err(error) => error.into_compile_error().into(),
    }
}

fn expand(input: TokenStream) -> syn::Result<TokenStream> {
    let directory = syn::parse::<LitStr>(input)?;
    let expanded = sqlx_macros_core::migrate::expand_migrator_from_lit_dir(directory.clone())
        .map_err(|error| syn::Error::new(directory.span(), error.to_string()))?;
    let mut expression = syn::parse2::<syn::Expr>(expanded)?;
    let service_kit = service_kit_path(&directory)?;

    SqlxPathRewriter { service_kit }.visit_expr_mut(&mut expression);
    Ok(quote!(#expression).into())
}

fn service_kit_path(directory: &LitStr) -> syn::Result<Path> {
    match crate_name("omnius-service-kit") {
        Ok(FoundCrate::Itself) => Ok(parse_quote!(crate)),
        Ok(FoundCrate::Name(name)) => {
            let normalized = name.replace('-', "_");
            syn::parse_str(&format!("::{normalized}"))
        }
        Err(error) => Err(syn::Error::new(
            directory.span(),
            format!("`migrate!` requires a direct dependency on `omnius-service-kit`: {error}"),
        )),
    }
}

struct SqlxPathRewriter {
    service_kit: Path,
}

impl VisitMut for SqlxPathRewriter {
    fn visit_path_mut(&mut self, path: &mut Path) {
        syn::visit_mut::visit_path_mut(self, path);
        if path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == "sqlx")
        {
            let mut replacement = self.service_kit.clone();
            replacement
                .segments
                .extend(path.segments.iter().skip(1).cloned());
            *path = replacement;
        }
    }
}
