// 보호 HWPX의 암호문 전용 저장·실패 보존·정책 재검사를 검증한다.
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

#[derive(Default)]
struct MockProvider {
    allowed: Arc<AtomicBool>,
    body: Arc<Mutex<Vec<u8>>>,
}

struct MockChannel(Arc<AtomicBool>, Arc<Mutex<Vec<u8>>>);

impl Provider for MockProvider {
    fn installed(&self) -> bool {
        true
    }
    fn automatic_encryption(&self) -> Result<bool, String> {
        Ok(self.allowed.load(Ordering::SeqCst))
    }
    fn open(&self, cipher: &[u8]) -> Result<Opened, String> {
        if !self.automatic_encryption()? || !is_encrypted(cipher) {
            return Err("denied".into());
        }
        Ok(Opened {
            hwpx: Zeroizing::new(self.body.lock().unwrap().clone()),
            channel: Box::new(MockChannel(self.allowed.clone(), self.body.clone())),
        })
    }
    fn create(&self, _name: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        MockChannel(self.allowed.clone(), self.body.clone()).encrypt(body)
    }
}
impl Channel for MockChannel {
    fn encrypt(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        if !self.0.load(Ordering::SeqCst) {
            return Err("denied".into());
        }
        *self.1.lock().unwrap() = body.to_vec();
        // 시험 파일에도 평문을 쓰지 않도록 본문은 메모리 제공자에만 보관한다.
        Ok(b"<DOCUMENTSAFER_0>opaque-test-envelope".to_vec())
    }
}

/// 합성 HWPX를 메모리에서 만들고 허용 정책의 시험 제공자와 함께 반환한다.
fn fixture() -> (Vec<u8>, Arc<MockProvider>, ManagedDocuments) {
    let mut core = hop_rhwp_adapter::DocumentCore::new_empty();
    core.create_blank_document_native().unwrap();
    let body = core.export_hwpx_native().unwrap();
    let provider = Arc::new(MockProvider::default());
    provider.allowed.store(true, Ordering::SeqCst);
    let manager = ManagedDocuments::new(Some(provider.clone()));
    (body, provider, manager)
}

#[test]
fn new_and_existing_roundtrip_write_only_ciphertext() {
    let (body, provider, mut manager) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.hwpx");
    manager.begin("new".into()).unwrap();
    manager.save("new", &path, &body).unwrap();
    assert!(is_encrypted(&std::fs::read(&path).unwrap()));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    manager.close("new");
    assert_eq!(
        manager.open("again".into(), &path).unwrap().as_slice(),
        body
    );
    manager.save("again", &path, &body).unwrap();
    provider.allowed.store(false, Ordering::SeqCst);
    let before = std::fs::read(&path).unwrap();
    assert!(manager.save("again", &path, &body).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn denied_policy_invalid_bytes_and_wrong_id_create_no_files() {
    let (body, provider, mut manager) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.hwpx");
    provider.allowed.store(false, Ordering::SeqCst);
    assert!(manager.begin("id".into()).is_err());
    provider.allowed.store(true, Ordering::SeqCst);
    manager.begin("id".into()).unwrap();
    assert!(manager.save("wrong", &path, &body).is_err());
    assert!(manager.save("id", &path, b"PK\x03\x04not-hwpx").is_err());
    assert!(manager
        .save("id", &dir.path().join("new.hwp"), &body)
        .is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn original_conflict_and_save_as_are_refused() {
    let (body, _, mut manager) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("original.hwpx");
    manager.begin("id".into()).unwrap();
    manager.save("id", &path, &body).unwrap();
    assert!(manager
        .save("id", &dir.path().join("copy.hwpx"), &body)
        .is_err());
    std::fs::write(&path, b"<DOCUMENTSAFER_0>external-change").unwrap();
    assert!(manager.save("id", &path, &body).is_err());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"<DOCUMENTSAFER_0>external-change"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn symlink_and_existing_new_target_are_refused() {
    let (body, _, mut manager) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("original.hwpx");
    std::fs::write(&path, b"<DOCUMENTSAFER_0>existing").unwrap();
    let link = dir.path().join("link.hwpx");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    manager.begin("id".into()).unwrap();
    assert!(manager.save("id", &link, &body).is_err());
    assert!(manager.save("id", &path, &body).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"<DOCUMENTSAFER_0>existing");
}
