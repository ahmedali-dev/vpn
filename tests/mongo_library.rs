//! Exercises the official driver against a tiny local wire fixture, without external credentials.
//! This verifies adapter commands and encryption, not Atlas or replica-set compatibility.
use mongodb::bson::{self, Bson, Document, doc};
use std::{
    collections::BTreeMap,
    io::Cursor,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tunnelnest::{
    infrastructure::mongo_library::{MongoLibrary, Settings},
    store::{Profile, Store},
};
type Records = Arc<Mutex<BTreeMap<String, Document>>>;
fn matches(record: &Document, filter: &Document) -> bool {
    filter.iter().all(|(k, v)| {
        if let Bson::Document(op) = v {
            op.get_str("$gt")
                .is_ok_and(|after| record.get_str(k).is_ok_and(|s| s > after))
        } else {
            record.get(k) == Some(v)
        }
    })
}
fn command(d: Document, records: &Records) -> Document {
    if d.contains_key("hello") || d.contains_key("isMaster") || d.contains_key("ismaster") {
        return doc! {"ok":1.0,"isWritablePrimary":true,"ismaster":true,"minWireVersion":0,"maxWireVersion":25,"maxBsonObjectSize":16777216,"maxMessageSizeBytes":48000000,"maxWriteBatchSize":100000,"connectionId":1};
    }
    if d.contains_key("update") {
        let u = d.get_array("updates").unwrap()[0].as_document().unwrap();
        let q = u.get_document("q").unwrap();
        let changes = u.get_document("u").unwrap();
        let id = q.get_str("_id").unwrap();
        let mut records = records.lock().unwrap();
        let exists = records.contains_key(id);
        let row = records.entry(id.into()).or_insert_with(|| doc! {"_id":id});
        if let Ok(set) = changes.get_document("$set") {
            row.extend(set.clone());
        }
        if !exists && let Ok(set) = changes.get_document("$setOnInsert") {
            row.extend(set.clone());
        }
        return doc! {"ok":1.0,"n":1,"nModified":if exists{1}else{0}};
    }
    if d.contains_key("find") {
        let filter = d.get_document("filter").unwrap();
        let limit = d.get_i64("limit").unwrap_or(25).unsigned_abs() as usize;
        let batch: Vec<Bson> = records
            .lock()
            .unwrap()
            .values()
            .filter(|r| matches(r, filter))
            .take(limit)
            .cloned()
            .map(Bson::Document)
            .collect();
        return doc! {"ok":1.0,"cursor":{"id":0_i64,"ns":format!("{}.{}",d.get_str("$db").unwrap_or("test"),d.get_str("find").unwrap()),"firstBatch":batch}};
    }
    if d.contains_key("delete") {
        let q = d.get_array("deletes").unwrap()[0]
            .as_document()
            .unwrap()
            .get_document("q")
            .unwrap();
        let mut records = records.lock().unwrap();
        let n = records.len();
        records.retain(|_, v| !matches(v, q));
        return doc! {"ok":1.0,"n":(n-records.len()) as i32};
    }
    doc! {"ok":1.0}
}
async fn serve(mut socket: TcpStream, records: Records) {
    loop {
        let mut h = [0_u8; 16];
        if socket.read_exact(&mut h).await.is_err() {
            break;
        }
        let length = i32::from_le_bytes(h[..4].try_into().unwrap()) as usize;
        if !(16..=1024 * 1024).contains(&length) {
            break;
        }
        let mut body = vec![0; length - 16];
        if socket.read_exact(&mut body).await.is_err() {
            break;
        }
        let opcode = i32::from_le_bytes(h[12..16].try_into().unwrap());
        let start = if opcode == 2013 {
            5
        } else if opcode == 2004 {
            let end = body[4..].iter().position(|c| *c == 0).unwrap() + 4;
            end + 9
        } else {
            break;
        };
        let request = Document::from_reader(&mut Cursor::new(&body[start..])).unwrap();
        let answer = command(request, &records);
        let raw = bson::to_vec(&answer).unwrap();
        let mut payload = Vec::new();
        if opcode == 2013 {
            payload.extend_from_slice(&0_i32.to_le_bytes());
            payload.push(0);
        } else {
            payload.extend_from_slice(&0_i32.to_le_bytes());
            payload.extend_from_slice(&0_i64.to_le_bytes());
            payload.extend_from_slice(&0_i32.to_le_bytes());
            payload.extend_from_slice(&1_i32.to_le_bytes());
        }
        payload.extend(raw);
        let mut response = Vec::new();
        response.extend_from_slice(&((16 + payload.len()) as i32).to_le_bytes());
        response.extend_from_slice(&1_i32.to_le_bytes());
        response.extend_from_slice(&h[4..8]);
        response.extend_from_slice(&(if opcode == 2013 { 2013_i32 } else { 1_i32 }).to_le_bytes());
        response.extend(payload);
        if socket.write_all(&response).await.is_err() {
            break;
        }
    }
}
fn settings(port: u16) -> Settings {
    Settings {
        uri: format!("mongodb://127.0.0.1:{port}/?directConnection=true"),
        database: "test".into(),
        collection: "profiles".into(),
        library: "personal".into(),
        passphrase: "shared library secret passphrase".into(),
        remember: false,
    }
}
fn profile() -> Profile {
    Profile {
        name: "private profile name".into(),
        mode: "ssh".into(),
        args: [
            "-mode",
            "ssh",
            "-H",
            "example.com",
            "-P",
            "443",
            "-u",
            "private-user",
            "-p",
            "private-password",
        ]
        .map(str::to_owned)
        .to_vec(),
        ..Profile::default()
    }
}
#[tokio::test]
async fn cross_device_library_encrypts_upserts_imports_and_rejects_wrong_password() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let records: Records = Default::default();
    let db = records.clone();
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(serve(socket, db.clone()));
        }
    });
    let first = MongoLibrary::connect(&settings(port)).await.unwrap();
    let second = MongoLibrary::connect(&settings(port)).await.unwrap();
    let id = MongoLibrary::new_id();
    first.save(&id, profile()).await.unwrap();
    first.save(&id, profile()).await.unwrap();
    let all = second.list("").await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["name"], "private profile name");
    assert_eq!(
        second.get(&id).await.unwrap().args,
        tunnelnest::features::profiles::prepare_for_save(profile())
            .unwrap()
            .args
    );
    let dump = format!("{:?}", records.lock().unwrap());
    for secret in ["private profile name", "private-user", "private-password"] {
        assert!(!dump.contains(secret));
    }
    let mut wrong = settings(port);
    wrong.passphrase = "a completely different passphrase".into();
    assert!(MongoLibrary::connect(&wrong).await.is_err());
    let dir = tempfile::tempdir().unwrap();
    let mut local = Store::open_password(&dir.path().join("profiles.sqlite3")).unwrap();
    local.unlock("local vault password").unwrap();
    let saved = local.import(second.get(&id).await.unwrap()).unwrap();
    local.link_cloud(saved.id, &second.scope, &id).unwrap();
    assert_eq!(local.cloud_id(saved.id, &second.scope).unwrap(), id);
    second.delete(&id).await.unwrap();
    assert!(first.list("").await.unwrap().is_empty());
    assert_eq!(local.get(saved.id).unwrap().name, "private profile name");
    server.abort();
}
#[tokio::test]
async fn session_only_credentials_cannot_be_uploaded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let records: Records = Default::default();
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(serve(socket, records.clone()));
        }
    });
    let lib = MongoLibrary::connect(&settings(port)).await.unwrap();
    let mut p = profile();
    p.session_only = true;
    assert!(
        lib.save(&MongoLibrary::new_id(), p)
            .await
            .unwrap_err()
            .to_string()
            .contains("Remember credentials")
    );
    server.abort();
}
