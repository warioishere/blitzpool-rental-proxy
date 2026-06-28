// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQLite connection pool + schema migrations for the proxy's persistent state
//! (rigs + orders). Embedded, single-file, ACID; WAL for concurrent reads.

use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

/// Open (creating if missing) the SQLite DB at `url` and run migrations.
///
/// `url` is a sqlx SQLite URL, e.g. `sqlite:///var/lib/rental-proxy/state.db`
/// or `sqlite::memory:` for tests. In-memory DBs are pinned to a single
/// connection so the whole pool shares the one ephemeral database.
pub async fn connect(url: &str) -> anyhow::Result<SqlitePool> {
    let memory = url.contains(":memory:");

    let mut opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .foreign_keys(true);
    if !memory {
        // WAL is meaningless for an in-memory DB; only set it for files.
        opts = opts.journal_mode(SqliteJournalMode::Wal);
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(if memory { 1 } else { 5 })
        .connect_with(opts)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

#[cfg(test)]
pub async fn test_pool() -> SqlitePool {
    connect("sqlite::memory:").await.expect("in-memory db")
}
