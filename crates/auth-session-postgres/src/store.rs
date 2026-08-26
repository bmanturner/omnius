use async_trait::async_trait;
use rsk_postgres::PostgresPool;
use serde_json::{Map, Value};
use tower_sessions::{
    SessionStore,
    session::{Id, Record},
    session_store::{self, ExpiredDeletion},
};
use tower_sessions_sqlx_store::PostgresStore;

const TYPE_KEY: &str = "t";
const VALUE_KEY: &str = "v";

/// PostgreSQL session store with a feature-stable value codec.
///
/// The maintained `SQLx` store serializes records through `MessagePack`. A session
/// record contains `serde_json::Value`; with `serde_json/arbitrary_precision`,
/// its number representation is JSON-specific and does not round-trip through
/// non-JSON serializers. This adapter keeps the maintained provider and wraps
/// every session value in a number-free tagged representation before storage.
#[derive(Clone, Debug)]
pub struct PostgresSessionStore {
    inner: PostgresStore,
}

impl PostgresSessionStore {
    /// Creates a store backed by the maintained PostgreSQL provider.
    #[must_use]
    pub fn new(pool: &PostgresPool) -> Self {
        Self {
            inner: PostgresStore::new(pool.sqlx_pool().clone()),
        }
    }
}

#[async_trait]
impl SessionStore for PostgresSessionStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        let mut encoded = encode_record(record);
        self.inner.create(&mut encoded).await?;
        record.id = encoded.id;
        Ok(())
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        self.inner.save(&encode_record(record)).await
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        self.inner
            .load(session_id)
            .await?
            .map(decode_record)
            .transpose()
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        self.inner.delete(session_id).await
    }
}

#[async_trait]
impl ExpiredDeletion for PostgresSessionStore {
    async fn delete_expired(&self) -> session_store::Result<()> {
        self.inner.delete_expired().await
    }
}

fn encode_record(record: &Record) -> Record {
    Record {
        id: record.id,
        data: record
            .data
            .iter()
            .map(|(key, value)| (key.clone(), encode_value(value)))
            .collect(),
        expiry_date: record.expiry_date,
    }
}

fn decode_record(mut record: Record) -> session_store::Result<Record> {
    record.data = record
        .data
        .into_iter()
        .map(|(key, value)| decode_value(value).map(|value| (key, value)))
        .collect::<session_store::Result<_>>()?;
    Ok(record)
}

fn encode_value(value: &Value) -> Value {
    match value {
        Value::Null => tagged("null", None),
        Value::Bool(value) => tagged("bool", Some(Value::Bool(*value))),
        Value::Number(value) => tagged("number", Some(Value::String(value.to_string()))),
        Value::String(value) => tagged("string", Some(Value::String(value.clone()))),
        Value::Array(values) => tagged(
            "array",
            Some(Value::Array(values.iter().map(encode_value).collect())),
        ),
        Value::Object(values) => tagged(
            "object",
            Some(Value::Array(
                values
                    .iter()
                    .map(|(key, value)| {
                        Value::Array(vec![Value::String(key.clone()), encode_value(value)])
                    })
                    .collect(),
            )),
        ),
    }
}

fn tagged(kind: &'static str, value: Option<Value>) -> Value {
    let mut object = Map::new();
    object.insert(TYPE_KEY.to_owned(), Value::String(kind.to_owned()));
    if let Some(value) = value {
        object.insert(VALUE_KEY.to_owned(), value);
    }
    Value::Object(object)
}

fn decode_value(value: Value) -> session_store::Result<Value> {
    let Value::Object(mut object) = value else {
        return Err(codec_error("session value is not a tagged object"));
    };
    let Some(Value::String(kind)) = object.remove(TYPE_KEY) else {
        return Err(codec_error("session value has no type tag"));
    };
    let payload = object.remove(VALUE_KEY);
    if !object.is_empty() {
        return Err(codec_error("session value has unexpected fields"));
    }
    match (kind.as_str(), payload) {
        ("null", None) => Ok(Value::Null),
        ("bool", Some(Value::Bool(value))) => Ok(Value::Bool(value)),
        ("number", Some(Value::String(value))) => value
            .parse()
            .map(Value::Number)
            .map_err(|_| codec_error("session value has an invalid number")),
        ("string", Some(Value::String(value))) => Ok(Value::String(value)),
        ("array", Some(Value::Array(values))) => values
            .into_iter()
            .map(decode_value)
            .collect::<session_store::Result<_>>()
            .map(Value::Array),
        ("object", Some(Value::Array(entries))) => decode_object(entries),
        _ => Err(codec_error("session value tag and payload do not match")),
    }
}

fn decode_object(entries: Vec<Value>) -> session_store::Result<Value> {
    let mut object = Map::new();
    for entry in entries {
        let Value::Array(mut pair) = entry else {
            return Err(codec_error("session object entry is not a pair"));
        };
        if pair.len() != 2 {
            return Err(codec_error("session object entry is not a pair"));
        }
        let Some(encoded) = pair.pop() else {
            return Err(codec_error("session object entry has no value"));
        };
        let Some(Value::String(key)) = pair.pop() else {
            return Err(codec_error("session object key is not a string"));
        };
        if object.insert(key, decode_value(encoded)?).is_some() {
            return Err(codec_error("session object contains a duplicate key"));
        }
    }
    Ok(Value::Object(object))
}

fn codec_error(message: &'static str) -> session_store::Error {
    session_store::Error::Decode(message.to_owned())
}
