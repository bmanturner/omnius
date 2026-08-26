# rsk-graphql

Optional bounded GraphQL-over-HTTP transport. Product fields and business rules remain in application-owned query and mutation roots and injected application services.

## Composition

```rust,ignore
let router = rsk_graphql::graphql_router(
    query_root,
    mutation_root,
    graphql_config,
    move |request, request_context| {
        let batch_item_limit = request_context.batch_item_limit();
        let loader = rsk_graphql::AuthorizedBatchLoader::new(
            application_query_service.clone(),
            canonical_authorizer.clone(),
            read_action.clone(),
            request_context,
            batch_item_limit,
        )
        .into_data_loader();
        request.data(loader)
    },
)?;
```

`graphql_router` returns an Axum `Router` exposing only `POST /graphql`. Compose authentication and tenancy middleware outside it so each request carries canonical `rsk_auth_core::Principal` and `rsk_authz_basic::AuthorizationContext` extensions. The transport inserts `Arc<GraphqlRequestContext>` and then invokes `RequestDataInjector` to attach application services and request-scoped DataLoaders.

`GraphqlTransport::new` exposes the same construction with access to the bounded schema before `into_router`. The schema always uses `EmptySubscription`; subscription operations return `SUBSCRIPTION_NOT_SUPPORTED` and hand clients to the separate realtime transport.

## Enforced policy

- validated depth, complexity, validation-recursion, list, request-body, serialized-response, and execution-time limits;
- cancellation token and absolute deadline propagated through `GraphqlRequestContext`;
- optional SHA-256 persisted-operation allowlist;
- introspection disabled by default and impossible to enable in production configuration;
- per-object canonical authorization in `AuthorizedBatchLoader`;
- stable GraphQL errors containing `code` and `requestId`, with resolver/internal detail removed;
- recursive input and output list enforcement, a validated DataLoader batch bound, and `BoundedList` collection that stops before an oversized iterator is materialized.
- one bounded JSON serialization pass with no partial-output path; oversized scalar or aggregate responses become `GRAPHQL_RESPONSE_TOO_LARGE`;
- response validation and serialization are checked against the same absolute execution deadline.

Application resolvers that expose lists must return `BoundedList<T>` and collect from a bounded or lazy application-service iterator with `GraphqlRequestContext::batch_item_limit()`. The final response walk is a fail-closed backstop for third-party output types; `BoundedList` is the allocation-safe source boundary.

The transport depends on `async-graphql` exactly `7.2.1` with default features disabled and only the `dataloader` feature enabled, plus `async-graphql-value` exactly `7.2.1` with default features disabled for executable-AST input values. It does not enable the playground, GraphiQL, dynamic-schema, email-validator, or tempfile features, and it does not depend on `async-graphql-axum`.
