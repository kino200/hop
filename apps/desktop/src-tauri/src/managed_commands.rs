// 전용 WebView에만 보호 문서 바이트를 전달하고 암호문 저장 명령을 제공한다.
use crate::{
    managed_document::{self, MAX_BYTES, RESTRICTED},
    state::{AppState, DocumentOpenResult, SaveResult},
};
use serde::Serialize;
use std::path::Path;
use tauri::{State, WebviewWindow};
use zeroize::Zeroizing;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedOpen {
    document: Option<DocumentOpenResult>,
    bytes: Vec<u8>,
    redirected: bool,
}

/// 현재 창이 파일·저장소 권한 없는 전용 보호 창인지 확인한다.
fn require_protected(window: &WebviewWindow, state: &AppState) -> Result<(), String> {
    if !state.protected || window.label() != "managed" {
        return Err(RESTRICTED.into());
    }
    Ok(())
}

/// 현재 프로세스의 보호 상태를 UI 초기화에 전달한다.
#[tauri::command]
pub fn document_safer_status(state: State<'_, AppState>) -> bool {
    state.protected
}

/// 새 보호 초안을 생성하고 추적 정보를 반환한다. 자동암호화 정책이 없으면 거부한다.
#[tauri::command]
pub fn create_managed_document(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<DocumentOpenResult, String> {
    require_protected(&window, &state)?;
    let id = uuid::Uuid::new_v4().to_string();
    let mut managed = state.managed.lock().map_err(|_| RESTRICTED)?;
    managed.begin(id.clone())?;
    Ok(state
        .sessions
        .lock()
        .map_err(|_| RESTRICTED)?
        .track_managed(id, None))
}

/// 암호문을 전용 프로세스로 전달하거나 보호 창에 메모리 본문·추적 정보를 반환한다.
#[tauri::command]
pub fn open_managed_document(
    window: WebviewWindow,
    path: String,
    state: State<'_, AppState>,
) -> Result<Option<ManagedOpen>, String> {
    if !state.protected {
        if !managed_document::encrypted_path(Path::new(&path))? {
            return Ok(None);
        }
        crate::protected_window::launch_protected(Path::new(&path))?;
        return Ok(Some(ManagedOpen {
            document: None,
            bytes: Vec::new(),
            redirected: true,
        }));
    }
    require_protected(&window, &state)?;
    let id = uuid::Uuid::new_v4().to_string();
    let mut managed = state.managed.lock().map_err(|_| RESTRICTED)?;
    let bytes = managed.open(id.clone(), Path::new(&path))?;
    let path = Path::new(&path).canonicalize().map_err(|_| RESTRICTED)?;
    let document = state
        .sessions
        .lock()
        .map_err(|_| RESTRICTED)?
        .track_managed(id, Some(path));
    Ok(Some(ManagedOpen {
        document: Some(document),
        bytes: bytes.to_vec(),
        redirected: false,
    }))
}

/// 전용 창의 문서 ID·버전·HWPX 바이트를 현재 정책으로 암호화하고 저장 결과를 반환한다.
#[tauri::command]
pub fn save_managed_document(
    window: WebviewWindow,
    doc_id: String,
    target_path: String,
    revision: u64,
    bytes: Vec<u8>,
    state: State<'_, AppState>,
) -> Result<SaveResult, String> {
    let bytes = Zeroizing::new(bytes);
    require_protected(&window, &state)?;
    if bytes.len() > MAX_BYTES {
        return Err(RESTRICTED.into());
    }
    let mut managed = state.managed.lock().map_err(|_| RESTRICTED)?;
    let mut sessions = state.sessions.lock().map_err(|_| RESTRICTED)?;
    sessions.check_managed_save(&doc_id, revision)?;
    let path = managed.save(&doc_id, Path::new(&target_path), &bytes)?;
    sessions.finish_managed_save(&doc_id, path)
}
