// 서명된 DocumentSafer 연결 도구와 상속 소켓으로 HWPX 메모리 데이터를 교환한다.
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::managed_document::{Channel, Opened, Provider, MAX_BYTES};

mod icon;

const BRIDGE: &str = "/Library/PrivilegedHelperTools/com.markany.DocumentSaferEditorBridge";
const REQUIREMENT: &str =
    "=anchor apple generic and certificate leaf[subject.OU] = \"9N6VX5RKP7\" and identifier \"com.markany.DocumentSaferEditorBridge\"";
const FAILED: &str =
    "DocumentSafer connection failed. Start and sign in to DocumentSafer, and update HOP, DocumentSafer and the signed editor bridge together.";

pub struct DocumentSafer;

struct Connection {
    stream: UnixStream,
    child: Child,
    failed: bool,
}

/// 고정 연결 도구의 서명을 제한 시간 안에 확인한다. 실패·시간 초과는 오류로 반환한다.
fn verify_bridge() -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(10))
        .ok_or(FAILED)?;
    let mut check = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "-R", REQUIREMENT, BRIDGE])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| FAILED)?;
    loop {
        match check.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err("The DocumentSafer bridge signature is not trusted.".into())
                }
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = check.kill();
                let _ = check.wait();
                return Err(FAILED.into());
            }
        }
    }
}

/// 인자 없이 배포 서명된 연결을 인증하고 버전 5 채널을 반환한다.
fn connect() -> Result<Connection, String> {
    // 실행 전 교체·링크 공격을 막기 위해 연결 도구와 모든 부모를 root 전용 쓰기 경로로 제한한다.
    for path in Path::new(BRIDGE).ancestors() {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| FAILED)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.file_type().is_symlink()
        {
            return Err("The DocumentSafer bridge must be installed in a root-owned, non-writable directory.".into());
        }
    }
    verify_bridge()?;
    let (stream, peer) = UnixStream::pair().map_err(|_| FAILED)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| FAILED)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| FAILED)?;
    let child = Command::new(BRIDGE)
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(peer)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| FAILED)?;
    let mut connection = Connection {
        stream,
        child,
        failed: false,
    };
    if connection.request(0, &[])? != [5] {
        return Err(FAILED.into());
    }
    Ok(connection)
}

impl Provider for DocumentSafer {
    /// 암호문을 받아 인증된 관리앱이 반환한 형식과 메모리 본문을 반환한다.
    fn open(&self, ciphertext: &[u8]) -> Result<Opened, String> {
        let mut connection = connect()?;
        let mut bytes = connection.request(1, ciphertext)?;
        if bytes.first() != Some(&5) {
            return Err(FAILED.into());
        }
        bytes.remove(0);
        Ok(Opened {
            hwpx: bytes.into(),
            channel: Box::new(connection),
        })
    }

    /// 인자 없이 관리앱 또는 연결 도구 설치 여부를 반환한다. 연결 도구가 빠진 설치도 평문 저장으로 우회하지 않는다.
    fn installed(&self) -> bool {
        !matches!(std::fs::symlink_metadata(BRIDGE), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
            || objc2_app_kit::NSWorkspace::sharedWorkspace()
                .URLForApplicationWithBundleIdentifier(&objc2_foundation::NSString::from_str(
                    "com.markany.securedocs.app",
                ))
                .is_some()
    }

    /// 로그인한 관리앱의 현재 한글 자동암호화 결정을 반환한다. 연결 실패는 일반 저장으로 우회하지 않는다.
    fn automatic_encryption(&self) -> Result<bool, String> {
        match connect()?.request(3, &[])?.as_slice() {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(FAILED.into()),
        }
    }

    /// 새 파일명·HWPX 본문을 받아 관리앱에서 최초 암호화한 결과를 반환한다.
    fn create(&self, name: &str, hwpx: &[u8]) -> Result<Vec<u8>, String> {
        connect()?.named_request(4, name, hwpx)
    }

    /// 열기·저장이 끝난 암호문 경로에 잠금 아이콘을 붙인다. 표시 실패가 암호문 저장 결과를 바꾸지는 않는다.
    fn refresh_file_icon(&self, path: &Path) {
        if let Err(error) = icon::refresh(path) {
            log::warn!("DocumentSafer encrypted file icon update failed: {error}");
        }
    }
}

impl Connection {
    /// 작업·HWPX 기본 파일명·본문을 제한된 프레임으로 보내고 암호문을 반환한다.
    fn named_request(&mut self, operation: u8, name: &str, hwpx: &[u8]) -> Result<Vec<u8>, String> {
        if name.is_empty()
            || name.len() > 255
            || name.contains(['/', '\\', '\0'])
            || !name.to_ascii_lowercase().ends_with(".hwpx")
        {
            return Err(FAILED.into());
        }
        let length = u16::try_from(name.len()).map_err(|_| FAILED)?;
        let size = 2usize
            .checked_add(name.len())
            .and_then(|size| size.checked_add(hwpx.len()))
            .ok_or(FAILED)?;
        if size > MAX_BYTES {
            return Err(FAILED.into());
        }
        let mut data = Vec::with_capacity(size);
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(hwpx);
        let response = self.request(operation, &data);
        data.fill(0);
        response
    }

    /// 작업 코드와 바이트를 전송하고 제한된 응답을 반환한다. 실패한 연결은 재사용하지 않는다.
    fn request(&mut self, operation: u8, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if self.failed || bytes.len() > MAX_BYTES {
            return Err(FAILED.into());
        }
        let result = self.exchange(operation, bytes);
        if result.is_err() {
            self.failed = true;
            let _ = self.child.kill();
        }
        result
    }

    /// 작업 코드·바이트를 받아 고정 헤더와 제한된 본문을 교환한다. 본문은 파일이나 로그로 전달하지 않는다.
    fn exchange(&mut self, operation: u8, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let size = u32::try_from(bytes.len()).map_err(|_| FAILED)?;
        self.stream.write_all(&[operation]).map_err(|_| FAILED)?;
        self.stream
            .write_all(&size.to_be_bytes())
            .map_err(|_| FAILED)?;
        self.stream.write_all(bytes).map_err(|_| FAILED)?;
        let mut header = [0u8; 5];
        self.stream.read_exact(&mut header).map_err(|_| FAILED)?;
        let size = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if size > MAX_BYTES {
            return Err(FAILED.into());
        }
        let mut response = vec![0; size];
        self.stream.read_exact(&mut response).map_err(|_| FAILED)?;
        if header[0] != 0 {
            return Err("DocumentSafer refused the document or its editing policy/session. No plaintext was saved.".into());
        }
        Ok(response)
    }
}

impl Channel for Connection {
    /// 편집한 HWPX 바이트를 받아 같은 인증 세션에서 만든 암호문을 반환한다.
    fn encrypt(&mut self, hwpx: &[u8]) -> Result<Vec<u8>, String> {
        self.request(2, hwpx)
    }
}

impl Drop for Connection {
    /// 인자 없이 전용 연결 도구를 종료하고 회수한다. 반환값은 없다.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
