// HWPX 보호 문서의 메모리 암복호화와 현재 정책·원본 보존을 관리한다.
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

mod io;
#[cfg(test)]
mod tests;
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
pub const RESTRICTED: &str = "보호 문서는 전용 HOP 창에서 편집하고 암호화 HWPX로 저장해야 합니다.";

pub trait Channel: Send {
    /// 편집한 HWPX 바이트를 받아 원본 ID·ACL·정책을 유지한 암호문을 반환한다.
    fn encrypt(&mut self, hwpx: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct Opened {
    pub hwpx: Zeroizing<Vec<u8>>,
    pub channel: Box<dyn Channel>,
}

pub trait Provider: Send + Sync {
    /// 관리앱 또는 연결 도구의 설치 여부를 반환한다.
    fn installed(&self) -> bool;
    /// 현재 로그인·한글 자동암호화 정책을 검사하며 조회 실패는 오류로 반환한다.
    fn automatic_encryption(&self) -> Result<bool, String>;
    /// 암호문을 인증된 관리앱에 전달하고 메모리 HWPX와 전용 저장 채널을 반환한다.
    fn open(&self, ciphertext: &[u8]) -> Result<Opened, String>;
    /// 새 HWPX 파일명과 본문으로 최초 암호문을 반환한다.
    fn create(&self, name: &str, hwpx: &[u8]) -> Result<Vec<u8>, String>;
    /// 암호문 저장이 끝난 파일의 표시 배지를 갱신한다.
    fn refresh_file_icon(&self, _path: &Path) {}
}

pub struct Record {
    pub id: String,
    pub path: Option<PathBuf>,
    baseline: Zeroizing<Vec<u8>>,
    encrypted: bool,
}

#[derive(Default)]
pub struct ManagedDocuments {
    pub provider: Option<Arc<dyn Provider>>,
    record: Option<Record>,
}

/// 현재 플랫폼에서 인증된 네이티브 제공자를 반환한다. 다른 플랫폼에는 등록하지 않는다.
pub fn native_provider() -> Option<Arc<dyn Provider>> {
    #[cfg(target_os = "macos")]
    return Some(Arc::new(crate::document_safer::DocumentSafer));
    #[cfg(not(target_os = "macos"))]
    None
}

/// 파일 앞부분이 알려진 DocumentSafer 암호문인지 반환한다.
pub fn is_encrypted(bytes: &[u8]) -> bool {
    [
        b"<DOCUMENTSAFER_0>".as_slice(),
        b"<DOCUMENT SAFER V2010 R2>",
        b"<MARKANY_DOCUMENTSAFER4>",
        b"MONADNOCK__SODS",
    ]
    .iter()
    .any(|v| bytes.starts_with(v))
}

/// 일반 창에서 파일 내용을 노출하기 전에 암호문인지 제한된 헤더로 검사한다.
pub fn encrypted_path(path: &Path) -> Result<bool, String> {
    Ok(is_encrypted(&io::read_prefix(path, 32)?))
}

impl ManagedDocuments {
    /// 관리앱 제공자를 등록하고 아직 문서가 없는 관리 상태를 반환한다.
    pub fn new(provider: Option<Arc<dyn Provider>>) -> Self {
        Self {
            provider,
            record: None,
        }
    }

    /// 새 보호 초안의 ID를 기록한다. 기존 문서를 혼합하거나 정책 조회를 우회하지 않는다.
    pub fn begin(&mut self, id: String) -> Result<(), String> {
        if self.record.is_some() || !self.provider()?.automatic_encryption()? {
            return Err(RESTRICTED.into());
        }
        self.record = Some(Record {
            id,
            path: None,
            baseline: Zeroizing::new(Vec::new()),
            encrypted: false,
        });
        Ok(())
    }

    /// HWPX 경로와 문서 ID로 암호문을 열고 메모리 본문을 반환한다. 원본은 변경하지 않는다.
    pub fn open(&mut self, id: String, path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
        if self.record.is_some() {
            return Err(RESTRICTED.into());
        }
        let path = io::canonical_target(path)?;
        let baseline = Zeroizing::new(io::read_bounded(&path)?);
        let encrypted = is_encrypted(&baseline);
        let provider = self.provider()?;
        let body = if encrypted {
            provider.open(&baseline)?.hwpx
        } else {
            if !provider.automatic_encryption()? {
                return Err(RESTRICTED.into());
            }
            baseline.clone()
        };
        io::validate_hwpx(&body)?;
        self.record = Some(Record {
            id,
            path: Some(path.clone()),
            baseline,
            encrypted,
        });
        if encrypted {
            provider.refresh_file_icon(&path);
        }
        Ok(body)
    }

    /// 현재 문서 ID·목표 경로·HWPX를 재검증하고 암호문만 원자 저장한 경로를 반환한다.
    pub fn save(&mut self, id: &str, target: &Path, body: &[u8]) -> Result<PathBuf, String> {
        io::validate_hwpx(body)?;
        let path = io::canonical_target(target)?;
        let record = self
            .record
            .as_ref()
            .filter(|r| r.id == id)
            .ok_or(RESTRICTED)?;
        if record.path.as_ref().is_some_and(|p| p != &path) {
            return Err(RESTRICTED.into());
        }
        self.unchanged()?;
        if record.path.is_none() && path.exists() {
            return Err("새 보호 문서는 기존 파일을 덮어쓸 수 없습니다.".into());
        }
        let provider = self.provider()?;
        let cipher = if record.encrypted {
            provider.open(&record.baseline)?.channel.encrypt(body)?
        } else {
            if !provider.automatic_encryption()? {
                return Err(RESTRICTED.into());
            }
            provider.create(
                path.file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(RESTRICTED)?,
                body,
            )?
        };
        if cipher.len() > MAX_BYTES || !cipher.starts_with(b"<DOCUMENTSAFER_0>") {
            return Err(RESTRICTED.into());
        }
        self.unchanged()?;
        io::write_ciphertext(&path, &cipher, record.path.is_none())?;
        self.record = Some(Record {
            id: id.into(),
            path: Some(path.clone()),
            baseline: Zeroizing::new(cipher),
            encrypted: true,
        });
        provider.refresh_file_icon(&path);
        Ok(path)
    }

    /// 닫는 문서 ID가 일치할 때만 관리 바이트를 해제한다.
    pub fn close(&mut self, id: &str) {
        if self.record.as_ref().is_some_and(|r| r.id == id) {
            self.record = None;
        }
    }

    /// 신뢰한 제공자를 반환하고 미설치·미등록 상태는 기본 거부한다.
    fn provider(&self) -> Result<Arc<dyn Provider>, String> {
        self.provider
            .clone()
            .filter(|p| p.installed())
            .ok_or_else(|| RESTRICTED.into())
    }

    /// 열거나 저장한 이후 원본이 바뀌었으면 덮어쓰기를 거부한다.
    fn unchanged(&self) -> Result<(), String> {
        if let Some(record) = &self.record {
            if let Some(path) = &record.path {
                if Zeroizing::new(io::read_bounded(path)?) != record.baseline {
                    return Err("원본 파일이 변경되어 저장을 중단했습니다.".into());
                }
            }
        }
        Ok(())
    }
}
