use std::{collections::BTreeSet, path::Path};

use crate::{ModuleCatalog, state::validate_relative_path};

#[derive(Clone, Copy, Debug)]
pub(crate) struct ApplicationTemplateDescriptor {
    pub(crate) module: &'static str,
    pub(crate) path: &'static str,
    pub(crate) source: &'static str,
}

macro_rules! application_template {
    ($module:literal, $path:literal) => {
        ApplicationTemplateDescriptor {
            module: $module,
            path: $path,
            source: include_str!(concat!("../../../", $path)),
        }
    };
}

macro_rules! application_template_variant {
    ($module:literal, $path:literal) => {
        ApplicationTemplateDescriptor {
            module: $module,
            path: $path,
            source: include_str!(concat!("../application_templates/", $path)),
        }
    };
}

pub(crate) const APPLICATION_TEMPLATE_DESCRIPTORS: &[ApplicationTemplateDescriptor] = &[
    application_template_variant!("web-sdk-core", "contracts/permissions.json"),
    application_template_variant!("web-sdk-core", "contracts/capabilities.json"),
    application_template_variant!("web-sdk-core", "contracts/contract-manifest.json"),
    application_template_variant!("openapi", "contracts/openapi.json"),
    application_template!("web-sdk-core", ".node-version"),
    application_template!("web-sdk-core", "package.json"),
    application_template!("web-sdk-core", "pnpm-lock.yaml"),
    application_template!("web-sdk-core", "pnpm-workspace.yaml"),
    application_template!("web-sdk-core", "packages/web-sdk/package.json"),
    application_template_variant!("web-sdk-core", "packages/web-sdk/orval.config.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/tsconfig.json"),
    application_template!("web-sdk-core", "packages/web-sdk/tsconfig.build.json"),
    application_template!("web-sdk-core", "packages/web-sdk/tsconfig.ts7.json"),
    application_template!("web-sdk-core", "packages/web-sdk/vitest.config.ts"),
    application_template_variant!(
        "web-sdk-core",
        "packages/web-sdk/scripts/check-boundaries.mjs"
    ),
    application_template!(
        "web-sdk-core",
        "packages/web-sdk/scripts/generate-contract-metadata.mjs"
    ),
    application_template_variant!(
        "web-sdk-core",
        "packages/web-sdk/scripts/generate-http-client.mjs"
    ),
    application_template!(
        "web-sdk-core",
        "packages/web-sdk/scripts/generate-realtime.mjs"
    ),
    application_template_variant!(
        "web-sdk-core",
        "packages/web-sdk/scripts/http-generation.ts"
    ),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/auth.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/etag.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/idempotency.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/index.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/mutator.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/pagination.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/public-base.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/retry.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/transport.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/client/type-guards.ts"),
    application_template!("web-sdk-core", "packages/web-sdk/src/capabilities/index.ts"),
    application_template_variant!(
        "web-sdk-core",
        "packages/web-sdk/src/internal/generated/contract-metadata.ts"
    ),
    application_template_variant!(
        "web-sdk-core",
        "packages/web-sdk/src/internal/generated/http/core.ts"
    ),
    application_template!("web-sdk-core", "packages/web-sdk/test/capabilities.test.ts"),
    application_template_variant!(
        "web-sdk-core",
        "packages/web-sdk/test/http-generation.test.ts"
    ),
    application_template_variant!(
        "web-sdk-core",
        "packages/web-sdk/test/http-utilities.test.ts"
    ),
    application_template!("web-sdk-core", "packages/web-sdk/test/transport.test.ts"),
    application_template!("web-react", "web/package.json"),
    application_template!("web-react", "web/index.html"),
    application_template!("web-react", "web/tsconfig.json"),
    application_template!("web-react", "web/tsconfig.build.json"),
    application_template!("web-react", "web/tsconfig.ts7.json"),
    application_template_variant!("web-react", "web/src/app.tsx"),
    application_template!("web-react", "web/src/build-metadata.ts"),
    application_template_variant!("web-react", "web/src/components/app-shell.tsx"),
    application_template!("web-react", "web/src/components/request-states.tsx"),
    application_template!("web-react", "web/src/main.tsx"),
    application_template_variant!("web-react", "web/src/router.tsx"),
    application_template!("web-react", "web/src/routes/not-found-route.tsx"),
    application_template_variant!("web-react", "web/src/routes/status-route.tsx"),
    application_template!("web-react", "web/src/styles.css"),
    application_template!("web-react", "web/src/vite-env.d.ts"),
    application_template_variant!("web-react", "packages/web-sdk/src/react/core.ts"),
    application_template!("web-react", "packages/web-sdk/src/react/query-scope.ts"),
    application_template!("web-react", "packages/web-sdk/src/react/capabilities.ts"),
    application_template_variant!(
        "web-react",
        "packages/web-sdk/src/internal/generated/http/react-query.ts"
    ),
    application_template!("web-auth", "packages/web-sdk/src/auth/bearer.ts"),
    application_template_variant!("web-auth", "packages/web-sdk/src/auth/index.ts"),
    application_template!("web-auth", "packages/web-sdk/src/auth/none.ts"),
    application_template!("web-auth", "packages/web-sdk/src/auth/oidc.ts"),
    application_template!("web-auth", "packages/web-sdk/src/auth/routes.ts"),
    application_template!("web-auth", "packages/web-sdk/src/auth/session.ts"),
    application_template!("web-auth", "packages/web-sdk/src/auth/types.ts"),
    application_template!("web-auth", "packages/web-sdk/src/react/auth.ts"),
    application_template!("web-auth", "packages/web-sdk/test/auth.test.ts"),
    application_template!("web-auth", "packages/web-sdk/src/testing/core.ts"),
    application_template!(
        "web-authorization",
        "packages/web-sdk/src/authorization/index.ts"
    ),
    application_template!("web-realtime", "packages/web-sdk/src/testing/realtime.ts"),
    application_template!("web-realtime", "packages/web-sdk/src/realtime/index.ts"),
    application_template!("web-realtime", "packages/web-sdk/src/realtime/internals.ts"),
    application_template!("web-realtime", "packages/web-sdk/src/realtime/manager.ts"),
    application_template!(
        "web-realtime",
        "packages/web-sdk/src/realtime/query-effects.ts"
    ),
    application_template!("web-realtime", "packages/web-sdk/src/realtime/sse.ts"),
    application_template!("web-realtime", "packages/web-sdk/src/realtime/types.ts"),
    application_template!("web-realtime", "packages/web-sdk/src/realtime/websocket.ts"),
    application_template!("web-realtime", "packages/web-sdk/src/react/realtime.ts"),
    application_template!(
        "web-realtime",
        "packages/web-sdk/test/realtime-decoder.test.ts"
    ),
    application_template!(
        "web-realtime",
        "packages/web-sdk/test/realtime-manager.test.ts"
    ),
    application_template!(
        "web-realtime",
        "packages/web-sdk/test/realtime-query-effects.test.ts"
    ),
    application_template!(
        "web-realtime",
        "packages/web-sdk/test/realtime-react.test.ts"
    ),
    application_template!("web-realtime", "packages/web-sdk/test/realtime-sse.test.ts"),
    application_template!(
        "web-realtime",
        "packages/web-sdk/test/realtime-websocket.test.ts"
    ),
    application_template!(
        "web-realtime",
        "packages/web-sdk/src/internal/generated/realtime.ts"
    ),
    application_template!("web-uploads", "packages/web-sdk/test/primitives.test.ts"),
    application_template!("web-uploads", "packages/web-sdk/src/uploads/http.ts"),
    application_template!("web-uploads", "packages/web-sdk/src/uploads/index.ts"),
    application_template!("web-uploads", "packages/web-sdk/src/react/uploads.ts"),
    application_template!("web-uploads", "packages/web-sdk/test/uploads.test.ts"),
    application_template!("web-tenancy", "packages/web-sdk/src/react/tenant.ts"),
    application_template!("web-tenancy", "packages/web-sdk/test/tenant.test.ts"),
    application_template_variant!("web-static", "web/vite.config.ts"),
    application_template!("web-static", "web/tsconfig.e2e.json"),
    application_template!("web-static", "web/vitest.config.ts"),
    application_template_variant!("web-static", "web/test/setup.ts"),
    application_template_variant!("web-static", "web/test/generated-profile.test.tsx"),
    application_template_variant!("web-static", "web/playwright.config.ts"),
    application_template!("web-static", "web/browser-support.json"),
    application_template!("web-static", "web/e2e/generated-profile-fixture.mjs"),
    application_template!("web-static", "web/e2e/generated-profile.spec.ts"),
    application_template_variant!(
        "web-testing",
        "packages/web-sdk/test/generated-http.test.ts"
    ),
    application_template!("web-testing", "packages/web-sdk/test/react-auth.test.ts"),
    application_template!("web-forms", "packages/web-sdk/src/react/forms.ts"),
    application_template!("web-forms", "packages/web-sdk/test/forms.test.ts"),
    application_template!(
        "web-local-state",
        "packages/web-sdk/src/react/local-state.ts"
    ),
    application_template!(
        "web-local-state",
        "packages/web-sdk/test/local-state.test.ts"
    ),
    application_template!("web-llm", "packages/web-sdk/src/llm/index.ts"),
    application_template!("web-llm", "packages/web-sdk/src/llm/stream.ts"),
    application_template!("web-llm", "packages/web-sdk/src/llm/types.ts"),
    application_template!("web-llm", "packages/web-sdk/src/react/llm.ts"),
    application_template!("web-llm", "packages/web-sdk/test/llm-stream.test.ts"),
];

pub(crate) fn application_template(
    module: &str,
    path: &str,
) -> Option<&'static ApplicationTemplateDescriptor> {
    APPLICATION_TEMPLATE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.module == module && descriptor.path == path)
}

pub(crate) fn validate_application_template_catalog(catalog: &ModuleCatalog) -> Result<(), String> {
    let mut embedded = BTreeSet::new();
    let mut embedded_paths = BTreeSet::new();
    for descriptor in APPLICATION_TEMPLATE_DESCRIPTORS {
        validate_application_template_path(descriptor.path)?;
        if !embedded.insert((descriptor.module, descriptor.path)) {
            return Err(format!(
                "duplicate embedded application template `{}` for module `{}`",
                descriptor.path, descriptor.module
            ));
        }
        if !embedded_paths.insert(descriptor.path) {
            return Err(format!(
                "application template `{}` is assigned to more than one module",
                descriptor.path
            ));
        }
    }

    let mut declared = BTreeSet::new();
    for module in &catalog.modules {
        for path in &module.application_templates {
            validate_application_template_path(path)?;
            if !declared.insert((module.id.as_str(), path.as_str())) {
                return Err(format!(
                    "module `{}` declares application template `{path}` more than once",
                    module.id
                ));
            }
        }
    }

    if let Some((module, path)) = declared.difference(&embedded).next() {
        return Err(format!(
            "module `{module}` declares application template `{path}` without embedded bytes"
        ));
    }
    if let Some((module, path)) = embedded.difference(&declared).next() {
        return Err(format!(
            "embedded application template `{path}` is not declared by module `{module}`"
        ));
    }
    Ok(())
}

fn validate_application_template_path(path: &str) -> Result<(), String> {
    validate_relative_path(path).map_err(|error| error.to_string())?;
    let forbidden = path == ".sqlx"
        || path.starts_with(".sqlx/")
        || path.starts_with("crates/")
        || path.starts_with("migrations/")
        || path.starts_with("specs/")
        || path.starts_with("templates/")
        || Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"));
    if forbidden {
        return Err(format!(
            "application template path `{path}` crosses the thin application boundary"
        ));
    }
    Ok(())
}
