use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode, header},
    middleware::Next,
};
use omnius_auth_core::{SessionConfig, SessionSameSite};
use omnius_postgres::PostgresPool;
use thiserror::Error;
use time::OffsetDateTime;
use tower_sessions::cookie::{Cookie, CookieJar};

/// State for response-time revocation enforcement and idle-cookie refresh.
///
/// Apply [`guard_revoked_session`] outside the session manager. It closes the
/// response-save race where an in-flight modified request could otherwise
/// recreate a provider row after account-management revocation committed.
#[derive(Clone)]
pub struct SessionRevocationGuard {
    pool: PostgresPool,
    idle_timeout: std::time::Duration,
    cookie_name: String,
    cookie_attributes: String,
    removal_cookie: HeaderValue,
}

impl SessionRevocationGuard {
    /// Builds a guard from the same pool and cookie policy as the session layer.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured cookie policy cannot form a header.
    pub fn new(pool: PostgresPool, config: &SessionConfig) -> Result<Self, SessionGuardError> {
        let same_site = match config.same_site {
            SessionSameSite::Lax => "Lax",
            SessionSameSite::Strict => "Strict",
        };
        let mut attributes = format!("Path=/; SameSite={same_site}");
        if config.http_only {
            attributes.push_str("; HttpOnly");
        }
        if config.secure {
            attributes.push_str("; Secure");
        }
        let removal_cookie =
            HeaderValue::from_str(&format!("{}=; {attributes}; Max-Age=0", config.cookie_name))
                .map_err(|_| SessionGuardError::InvalidCookieHeader)?;
        Ok(Self {
            pool,
            idle_timeout: config.idle_timeout,
            cookie_name: config.cookie_name.clone(),
            cookie_attributes: attributes,
            removal_cookie,
        })
    }

    fn active_cookie(&self, session_id: &str) -> Result<HeaderValue, SessionGuardError> {
        HeaderValue::from_str(&format!(
            "{}={session_id}; {}; Max-Age={}",
            self.cookie_name,
            self.cookie_attributes,
            self.idle_timeout.as_secs()
        ))
        .map_err(|_| SessionGuardError::InvalidCookieHeader)
    }
}

/// Stable response-guard construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionGuardError {
    /// The configured cookie policy could not form a response header.
    #[error("session cookie header is invalid")]
    InvalidCookieHeader,
}

/// Rejects response-saved revoked sessions and refreshes active idle cookies.
///
/// This middleware must wrap the session manager so it observes the final
/// `Set-Cookie` header after the maintained store has completed its response
/// save.
pub async fn guard_revoked_session(
    State(guard): State<SessionRevocationGuard>,
    request: Request,
    next: Next,
) -> Response<Body> {
    let request_session_id = request_session_id(&request, &guard.cookie_name);
    let mut response = next.run(request).await;
    if response_removes_session(&response, &guard.cookie_name) {
        return response;
    }
    let session_id = response_session_id(&response, &guard.cookie_name).or(request_session_id);
    let Some(session_id) = session_id else {
        return response;
    };
    let Ok(idle_timeout) = time::Duration::try_from(guard.idle_timeout) else {
        return fail_closed_response(response, &guard);
    };
    let Some(idle_cutoff) = OffsetDateTime::now_utc().checked_sub(idle_timeout) else {
        return fail_closed_response(response, &guard);
    };

    let active = sqlx::query_scalar::<_, Option<bool>>(
        "WITH lifecycle AS ( \
           SELECT revoked_at IS NULL AND absolute_expires_at > now() \
                  AND last_seen_at > $2 AS active \
           FROM sessions WHERE session_id = $1 \
         ), deleted AS ( \
           DELETE FROM tower_sessions.session \
           WHERE id = $1 AND EXISTS (SELECT 1 FROM lifecycle WHERE NOT active) \
         ) SELECT (SELECT active FROM lifecycle)",
    )
    .bind(&session_id)
    .bind(idle_cutoff)
    .fetch_one(&guard.pool.sqlx_pool())
    .await;

    match active {
        Ok(Some(true)) => match guard.active_cookie(&session_id) {
            Ok(cookie) => {
                replace_session_cookie(&mut response, &guard.cookie_name, cookie);
                response
            }
            Err(_) => fail_closed_response(response, &guard),
        },
        Ok(Some(false)) => {
            replace_session_cookie(
                &mut response,
                &guard.cookie_name,
                guard.removal_cookie.clone(),
            );
            response
        }
        Ok(None) => response,
        Err(_) => fail_closed_response(response, &guard),
    }
}

fn fail_closed_response(
    mut response: Response<Body>,
    guard: &SessionRevocationGuard,
) -> Response<Body> {
    replace_session_cookie(
        &mut response,
        &guard.cookie_name,
        guard.removal_cookie.clone(),
    );
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

fn request_session_id(request: &Request, cookie_name: &str) -> Option<String> {
    let mut jar = CookieJar::new();
    for header in request.headers().get_all(header::COOKIE) {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for cookie in header.split(';') {
            if let Ok(cookie) = Cookie::parse_encoded(cookie.to_owned()) {
                jar.add_original(cookie);
            }
        }
    }
    jar.get(cookie_name)
        .filter(|cookie| !cookie.value().is_empty())
        .map(|cookie| cookie.value().to_owned())
}

fn response_session_id(response: &Response<Body>, cookie_name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('='))
        .filter(|(name, value)| *name == cookie_name && !value.is_empty())
        .map(|(_, value)| value.to_owned())
        .next_back()
}

fn response_removes_session(response: &Response<Body>, cookie_name: &str) -> bool {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('='))
        .any(|(name, value)| name == cookie_name && value.is_empty())
}

fn replace_session_cookie(
    response: &mut Response<Body>,
    cookie_name: &str,
    replacement: HeaderValue,
) {
    let retained = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|value| {
            value.to_str().map_or(true, |value| {
                value
                    .split(';')
                    .next()
                    .and_then(|pair| pair.split_once('='))
                    .is_none_or(|(name, _)| name != cookie_name)
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    response.headers_mut().remove(header::SET_COOKIE);
    for value in retained {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
        .headers_mut()
        .append(header::SET_COOKIE, replacement);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_cookie_parsing_matches_tower_cookie_jar_precedence_and_decoding()
    -> Result<(), axum::http::Error> {
        let request = Request::builder()
            .header(
                header::COOKIE,
                "__Host-omnius_session=first; __Host-omnius_session=second%2Dvalue",
            )
            .body(Body::empty())?;

        assert_eq!(
            request_session_id(&request, "__Host-omnius_session").as_deref(),
            Some("second-value")
        );
        Ok(())
    }
}
