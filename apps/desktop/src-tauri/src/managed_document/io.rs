// 보호 문서의 크기·형식을 제한하고 암호문만 비공개 임시 파일에 원자 저장한다.
use super::{MAX_BYTES, RESTRICTED};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// 일반 파일의 시작 바이트만 읽어 반환하며 심볼릭 링크는 거부한다.
pub(super) fn read_prefix(path: &Path, size: usize) -> Result<Vec<u8>, String> {
    if !fs::symlink_metadata(path)
        .map_err(|_| RESTRICTED)?
        .file_type()
        .is_file()
    {
        return Err(RESTRICTED.into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| RESTRICTED)?
        .take(size as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RESTRICTED)?;
    Ok(bytes)
}

/// 전체 문서를 상한보다 한 바이트까지만 읽고 과대 입력을 거부한다.
pub(super) fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = read_prefix(path, MAX_BYTES + 1)?;
    if bytes.len() > MAX_BYTES {
        return Err(RESTRICTED.into());
    }
    Ok(bytes)
}

/// HWPX 확장자·파일명·실제 부모 경로를 확인하고 일관된 저장 경로를 반환한다.
pub(super) fn canonical_target(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(RESTRICTED)?;
    if name.len() > 255
        || !name.to_ascii_lowercase().ends_with(".hwpx")
        || name.chars().any(|c| c.is_control())
    {
        return Err(RESTRICTED.into());
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file() {
            return Err(RESTRICTED.into());
        }
    }
    let parent = path
        .parent()
        .ok_or(RESTRICTED)?
        .canonicalize()
        .map_err(|_| RESTRICTED)?;
    Ok(parent.join(name))
}

/// 크기·ZIP 서명과 문서 파싱을 메모리에서 검사하며 오류 본문은 외부로 내보내지 않는다.
pub(super) fn validate_hwpx(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_BYTES || !bytes.starts_with(b"PK\x03\x04") {
        return Err(RESTRICTED.into());
    }
    // ZIP 서명만 있는 다른 형식을 HWPX로 암호화하지 않도록 엔진의 형식 판별도 검사한다.
    if !hop_rhwp_adapter::is_hwpx(bytes) {
        return Err(RESTRICTED.into());
    }
    hop_rhwp_adapter::DocumentCore::from_bytes(bytes)
        .map_err(|_| "유효한 HWPX 문서가 아닙니다.")?;
    Ok(())
}

/// 암호문을 대상 폴더의 0600 임시 파일에 기록하고 동기화한 뒤 원자 교체한다.
pub(super) fn write_ciphertext(path: &Path, bytes: &[u8], create: bool) -> Result<(), String> {
    if !bytes.starts_with(b"<DOCUMENTSAFER_0>") {
        return Err(RESTRICTED.into());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(path.parent().ok_or(RESTRICTED)?)
        .map_err(|_| "암호문 임시 파일을 만들 수 없습니다.")?;
    temporary
        .write_all(bytes)
        .map_err(|_| "암호문을 저장할 수 없습니다.")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "암호문 저장을 동기화할 수 없습니다.")?;
    if create {
        temporary.persist_noclobber(path)
    } else {
        temporary.persist(path)
    }
    .map_err(|_| "암호문 파일을 교체할 수 없습니다.")?;
    Ok(())
}
