use crate::crypto::{self, Password};
use crate::id::Id;
use flume::{Receiver, Sender};
use read::ListEntry;
use rusqlite::{Connection, Transaction, params};
use rusqlite_migration::{HookError, M, Migrations};
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::LazyLock;

static MIGRATIONS: LazyLock<Migrations> = LazyLock::new(|| {
    Migrations::new(vec![
        M::up(include_str!("migrations/0001-initial.sql")),
        M::up(include_str!("migrations/0002-add-created-column.sql")),
        M::up(include_str!(
            "migrations/0003-drop-created-add-uid-column.sql"
        )),
        M::up_with_hook(
            include_str!("migrations/0004-add-compressed-column.sql"),
            |tx: &Transaction| {
                let mut stmt = tx.prepare("SELECT id, text FROM entries")?;

                let rows = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<(u32, String)>, _>>()?;

                tracing::debug!("compressing {} rows", rows.len());

                for (id, text) in rows {
                    let cursor = Cursor::new(text);
                    let data = zstd::stream::encode_all(cursor, zstd::DEFAULT_COMPRESSION_LEVEL)
                        .map_err(|e| HookError::Hook(e.to_string()))?;

                    tx.execute(
                        "UPDATE entries SET data = ?1 WHERE id = ?2",
                        params![data, id],
                    )?;
                }

                Ok(())
            },
        ),
        M::up(include_str!("migrations/0005-drop-text-column.sql")),
        M::up(include_str!("migrations/0006-add-nonce-column.sql")),
        M::up(include_str!("migrations/0007-add-title-column.sql")),
    ])
});

/// Database related errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("not allowed to delete")]
    Delete,
    #[error("sqlite error: {0}")]
    Sqlite(rusqlite::Error),
    #[error("migrations error: {0}")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("failed to compress: {0}")]
    Compression(String),
    #[error("password not given")]
    NoPassword,
    #[error("entry not found")]
    NotFound,
    #[error("join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::Error),
    #[error("recv error: {0}")]
    Recv(#[from] flume::RecvError),
    #[error("send command error: {0}")]
    SendCommand(#[from] flume::SendError<DatabaseCommand>),
    #[error("send payload error: {0}")]
    SendPayload(#[from] flume::SendError<DatabasePayload>),
}

/// Our main database and integrated cache.
#[derive(Clone)]
pub struct Database {
    conn: Sender<(Sender<DatabaseResponse>, DatabaseCommand)>,
}

#[non_exhaustive]
pub enum DatabaseResponse {
    Insert(Result<usize, rusqlite::Error>),
}

pub enum DatabaseCommand {
    Insert {
        id: i64,
        entry: write::Entry,
        data: Vec<u8>,
        nonce: Option<Vec<u8>>,
    },
}

type DatabasePayload = (Sender<DatabaseResponse>, DatabaseCommand);

/// Database opening modes
#[derive(Debug)]
pub enum Open {
    /// Open in-memory database that is wiped after reload
    Memory,
    /// Open database from given path
    Path(PathBuf),
}

/// Module with types for insertion.
pub mod write {
    use crate::crypto::{Encrypted, Password, Plaintext};
    use crate::db::Error;
    use async_compression::tokio::bufread::ZstdEncoder;
    use serde::{Deserialize, Serialize};
    use std::io::Cursor;
    use std::num::NonZeroU32;
    use tokio::io::AsyncReadExt;

    /// An uncompressed entry to be inserted into the database.
    #[derive(Clone, Default, Debug, Serialize, Deserialize)]
    pub struct Entry {
        /// Content
        pub text: String,
        /// File extension
        pub extension: Option<String>,
        /// Expiration in seconds from now
        pub expires: Option<NonZeroU32>,
        /// Delete if read
        pub burn_after_reading: Option<bool>,
        /// User identifier that inserted the entry
        pub uid: Option<i64>,
        /// Optional password to encrypt the entry
        pub password: Option<String>,
        /// Title
        pub title: Option<String>,
    }

    /// A compressed entry to be inserted.
    pub struct CompressedEntry {
        /// Original data
        entry: Entry,
        /// Compressed data
        data: Vec<u8>,
    }

    /// An entry that might be encrypted.
    pub struct DatabaseEntry {
        /// Original data
        pub entry: Entry,
        /// Compressed and potentially encrypted data
        pub data: Vec<u8>,
        /// Nonce for this entry
        pub nonce: Option<Vec<u8>>,
    }

    impl Entry {
        /// Compress the entry for insertion.
        pub async fn compress(self) -> Result<CompressedEntry, Error> {
            let mut encoder = ZstdEncoder::new(Cursor::new(&self.text));
            let mut data = Vec::new();

            encoder
                .read_to_end(&mut data)
                .await
                .map_err(|e| Error::Compression(e.to_string()))?;

            Ok(CompressedEntry { entry: self, data })
        }
    }

    impl CompressedEntry {
        /// Encrypt if password is set.
        pub async fn encrypt(self) -> Result<DatabaseEntry, Error> {
            let (data, nonce) = if let Some(password) = &self.entry.password {
                let password = Password::from(password.as_bytes().to_vec());
                let plaintext = Plaintext::from(self.data);
                let Encrypted { ciphertext, nonce } = plaintext.encrypt(password).await?;
                (ciphertext, Some(nonce))
            } else {
                (self.data, None)
            };

            Ok(DatabaseEntry {
                entry: self.entry,
                data,
                nonce,
            })
        }
    }
}

/// Module with types for reading from the database.
pub mod read {
    use crate::crypto::{Encrypted, Password};
    use crate::db::Error;
    use crate::id::Id;
    use async_compression::tokio::bufread::ZstdDecoder;
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    /// A raw entry as read from the database.
    #[derive(Debug)]
    pub(crate) struct DatabaseEntry {
        /// Compressed and potentially encrypted data
        pub data: Vec<u8>,
        /// Entry is expired
        pub expired: bool,
        /// Entry must be deleted
        pub must_be_deleted: bool,
        /// User identifier that inserted the entry
        pub uid: Option<i64>,
        /// Nonce for this entry
        pub nonce: Option<Vec<u8>>,
        /// Title
        pub title: Option<String>,
    }

    /// Potentially decrypted but still compressed entry
    #[derive(Debug)]
    pub(crate) struct CompressedReadEntry {
        /// Compressed data
        data: Vec<u8>,
        /// Entry must be deleted
        must_be_deleted: bool,
        /// User identifier that inserted the entry
        uid: Option<i64>,
        /// Title
        title: Option<String>,
    }

    /// Uncompressed entry
    #[derive(Debug)]
    pub(crate) struct UmcompressedEntry {
        /// Content
        pub text: String,
        /// Entry must be deleted
        pub must_be_deleted: bool,
        /// User identifier that inserted the entry
        pub uid: Option<i64>,
        /// Title
        pub title: Option<String>,
    }

    /// Uncompressed, decrypted data read from the database.
    #[derive(Debug)]
    pub struct Data {
        /// Content
        pub text: String,
        /// User identifier that inserted the entry
        pub uid: Option<i64>,
        /// Title
        pub title: Option<String>,
    }

    /// Potentially deleted or non-existent expired entry.
    #[derive(Debug)]
    pub enum Entry {
        /// Entry found and still available.
        Regular(Data),
        /// Entry burned.
        Burned(Data),
    }

    /// A simple entry as read from the database for listing purposes.
    #[derive(Debug)]
    pub struct ListEntry {
        /// Identifier
        pub id: Id,
        /// Optional title
        pub title: Option<String>,
        /// If entry is encrypted
        pub is_encrypted: bool,
        /// If entry is expired
        pub is_expired: bool,
    }

    impl DatabaseEntry {
        pub async fn decrypt(
            self,
            password: Option<Password>,
        ) -> Result<CompressedReadEntry, Error> {
            match (self.nonce, password) {
                (Some(_), None) => Err(Error::NoPassword),
                (None, None | Some(_)) => Ok(CompressedReadEntry {
                    data: self.data,
                    must_be_deleted: self.must_be_deleted,
                    uid: self.uid,
                    title: self.title,
                }),
                (Some(nonce), Some(password)) => {
                    let encrypted = Encrypted::new(self.data, nonce);
                    let decrypted = encrypted.decrypt(password).await?;
                    Ok(CompressedReadEntry {
                        data: decrypted,
                        must_be_deleted: self.must_be_deleted,
                        uid: self.uid,
                        title: self.title,
                    })
                }
            }
        }
    }

    impl CompressedReadEntry {
        pub async fn decompress(self) -> Result<UmcompressedEntry, Error> {
            let mut decoder = ZstdDecoder::new(Cursor::new(self.data));
            let mut text = String::new();

            decoder
                .read_to_string(&mut text)
                .await
                .map_err(|e| Error::Compression(e.to_string()))?;

            Ok(UmcompressedEntry {
                text,
                uid: self.uid,
                must_be_deleted: self.must_be_deleted,
                title: self.title,
            })
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        match err {
            rusqlite::Error::QueryReturnedNoRows => Error::NotFound,
            _ => Error::Sqlite(err),
        }
    }
}

impl Database {
    /// Create new database with the given `method`.
    pub fn new(method: Open) -> Result<Self, Error> {
        tracing::debug!("opening {method:?}");

        let mut conn = match method {
            Open::Memory => Connection::open_in_memory()?,
            Open::Path(path) => Connection::open(path)?,
        };

        MIGRATIONS.to_latest(&mut conn)?;

        let (tx, rx) = flume::bounded(0);
        std::thread::spawn(move || {
            let (event_tx, event_rx): (Sender<DatabasePayload>, Receiver<DatabasePayload>) =
                flume::unbounded();
            let _ = tx.send(event_tx);
            while let Ok((resp_oneshot, command)) = event_rx.recv() {
                match command {
                    DatabaseCommand::Insert {
                        id,
                        entry,
                        nonce,
                        data,
                    } => {
                        let result = match entry.expires {
                            None => conn.execute(
                                "INSERT INTO entries (id, uid, data, burn_after_reading, nonce, title) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                params![id, entry.uid, data, entry.burn_after_reading, nonce, entry.title],
                            ),
                            Some(expires) => conn.execute(
                                "INSERT INTO entries (id, uid, data, burn_after_reading, nonce, expires, title) VALUES (?1, ?2, ?3, ?4, ?5, datetime('now', ?6), ?7)",
                                params![
                                    id,
                                    entry.uid,
                                    data,
                                    entry.burn_after_reading,
                                    nonce,
                                    format!("{expires} seconds"),
                                    entry.title,
                                ],
                            ),
                        };
                        let _ = resp_oneshot.send(DatabaseResponse::Insert(result));
                    }
                }
            }
        });

        let sender = rx.recv()?;

        Ok(Self { conn: sender })
    }

    /// Insert `entry` under `id` into the database and optionally set owner to `uid`.
    pub async fn insert(&self, id: Id, entry: write::Entry) -> Result<(), Error> {
        let conn = self.conn.clone();
        let write::DatabaseEntry { entry, data, nonce } = entry.compress().await?.encrypt().await?;

        let id = id.to_i64();
        let (tx, rx) = flume::bounded(0);
        self.conn.send((
            tx,
            DatabaseCommand::Insert {
                id,
                entry,
                data,
                nonce,
            },
        ))?;

        if let DatabaseResponse::Insert(resp) = rx.recv_async().await? {
            resp?;
        }

        Ok(())
    }

    /// Get entire entry for `id`.
    pub async fn get(&self, id: &Id, password: Option<Password>) -> Result<read::Entry, Error> {
        unimplemented!()
    }

    /// Get title of a paste.
    pub async fn get_title(&self, id: Id) -> Result<Option<String>, Error> {
        unimplemented!()
    }

    /// Delete paste with `id`.
    async fn delete(&self, id: Id) -> Result<(), Error> {
        unimplemented!()
    }

    /// Delete paste with `id` for user `uid`.
    pub async fn delete_for(&self, id: Id, uid: i64) -> Result<(), Error> {
        unimplemented!()
    }

    /// Retrieve next monotonically increasing uid.
    pub async fn next_uid(&self) -> Result<i64, Error> {
        unimplemented!()
    }

    /// List all entries.
    pub fn list(&self) -> Result<Vec<ListEntry>, Error> {
        unimplemented!()
    }

    /// Purge all expired entries and return their [`Id`]s
    pub fn purge(&self) -> Result<Vec<Id>, Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use super::*;

    impl read::Entry {
        /// Unwrap inner data or panic.
        pub fn unwrap_inner(self) -> read::Data {
            match self {
                read::Entry::Regular(data) => data,
                read::Entry::Burned(data) => data,
            }
        }
    }

    fn new_db() -> Result<Database, Box<dyn std::error::Error>> {
        Ok(Database::new(Open::Memory)?)
    }

    #[tokio::test]
    async fn insert() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let entry = write::Entry {
            text: "hello world".to_string(),
            uid: Some(10),
            ..Default::default()
        };

        let id = Id::from(1234u32);
        db.insert(id.clone(), entry).await?;

        let entry = db.get(&id, None).await?.unwrap_inner();
        assert_eq!(entry.text, "hello world");
        assert!(entry.uid.is_some());
        assert_eq!(entry.uid.unwrap(), 10);

        let result = db.get(&Id::from(5678u32), None).await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn expired_does_not_exist() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let entry = write::Entry {
            expires: Some(NonZero::new(1).unwrap()),
            ..Default::default()
        };

        let id = Id::from(1234u32);
        db.insert(id.clone(), entry).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let result = db.get(&id, None).await;
        assert!(matches!(result, Err(Error::NotFound)));

        Ok(())
    }

    #[tokio::test]
    async fn delete() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let id = Id::from(1234u32);
        db.insert(id.clone(), write::Entry::default()).await?;

        assert!(db.get(&id, None).await.is_ok());
        assert!(db.delete(id.clone()).await.is_ok());
        assert!(db.get(&id, None).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn purge() -> Result<(), Box<dyn std::error::Error>> {
        let db = new_db()?;

        let entry = write::Entry {
            expires: Some(NonZero::new(1).unwrap()),
            ..Default::default()
        };

        let id = Id::from(1234u32);
        db.insert(id, entry).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let ids = db.purge()?;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].to_i64(), 1234);

        Ok(())
    }
}
