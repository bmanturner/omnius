//! Executes a checked query whose metadata also compiles without a database.

use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    let database_url = std::env::var("DATABASE_URL").map_err(|error| {
        sqlx::Error::Configuration(format!("DATABASE_URL is required: {error}").into())
    })?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let value = sqlx::query_scalar!("SELECT value FROM phase0_probe WHERE id = $1", 1_i64)
        .fetch_one(&pool)
        .await?;
    if value != "offline-ready" {
        return Err(sqlx::Error::Protocol("unexpected probe value".into()));
    }
    pool.close().await;
    println!("checked query executed against PostgreSQL");
    Ok(())
}
