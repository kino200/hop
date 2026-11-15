// 보호 프로세스의 WebView 권한·접근성·네이티브 출력 경계를 제한한다.
use crate::{managed_document::RESTRICTED, state::AppState};
use std::path::Path;
use tauri::{AppHandle, Manager};

/// 비영속·캡처 제한 WebView를 만들고 다운로드·외부 탐색·새 창을 거부한다.
pub fn create(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = app
        .config()
        .app
        .windows
        .first()
        .cloned()
        .ok_or(RESTRICTED)?;
    config.label = "managed".into();
    config.incognito = true;
    config.devtools = Some(false);
    config.content_protected = true;
    let window = tauri::WebviewWindowBuilder::from_config(app, &config)?
        .initialization_script("Object.defineProperty(window, '__HOP_PROTECTED__', {value: true});")
        .on_navigation(allows_navigation)
        .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
        .on_download(|_, _| false)
        .on_page_load(|window, _| {
            let app = window.app_handle().clone();
            let handle = app.clone();
            let _ = app.run_on_main_thread(move || {
                if hide_accessibility(&handle).is_err() {
                    handle.exit(1);
                }
            });
        })
        .build()?;
    crate::windows::install_editor_window_minimum(&window);
    crate::windows::configure_editor_webview(app, &window);
    hide_accessibility(app)?;
    Ok(())
}

/// 페이지 주소가 앱에 포함된 시작 화면인지 반환한다. 외부·다른 페이지 탐색은 거부한다.
fn allows_navigation(url: &tauri::Url) -> bool {
    // Tauri는 index.html의 첫 주소에서 경로를 생략한다.
    matches!(
        url.as_str(),
        "tauri://localhost" | "tauri://localhost/" | "tauri://localhost/index.html"
    )
}

/// 보호 창이 호출할 수 있는 최소 네이티브 명령인지 반환한다.
pub fn allows_command(command: &str) -> bool {
    matches!(
        command,
        "document_safer_status"
            | "create_managed_document"
            | "open_managed_document"
            | "save_managed_document"
            | "close_document"
            | "mark_document_dirty"
            | "take_pending_open_paths"
            | "destroy_current_window"
            | "cancel_app_quit"
            | "desktop_platform"
            | "list_local_fonts"
            | "read_local_font"
            | "get_update_state"
    )
}

/// 일반 저장·인쇄 경로에서도 현재 자동암호화 정책을 확인해 보호 경로 우회를 거부한다.
pub fn require_plain_output(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    if state.protected {
        return Err(RESTRICTED.into());
    }
    let managed = state.managed.lock().map_err(|_| RESTRICTED)?;
    if let Some(provider) = &managed.provider {
        if provider.installed() && provider.automatic_encryption()? {
            return Err("자동암호화 정책이 적용되었습니다. 보호 문서 작업은 새 HOP 프로세스에서 시작해 주세요.".into());
        }
    }
    Ok(())
}

/// 기존 창의 문서를 변경하지 않고 같은 앱의 새 보호 프로세스에 암호문 경로만 전달한다.
pub fn launch_protected(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let executable = std::env::current_exe().map_err(|_| RESTRICTED)?;
        let bundle = executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or(RESTRICTED)?;
        if bundle.extension().and_then(|s| s.to_str()) != Some("app") {
            return Err(RESTRICTED.into());
        }
        let status = std::process::Command::new("/usr/bin/open")
            .arg("-n")
            .arg(bundle)
            .args(["--args", "--documentsafer"])
            .arg(path)
            .status()
            .map_err(|_| RESTRICTED)?;
        if status.success() {
            return Ok(());
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
    Err(RESTRICTED.into())
}

/// 보호 창의 네이티브 접근성 트리를 숨겨 WebView 본문이 외부 앱에 노출되지 않게 한다.
pub fn hide_accessibility(app: &AppHandle) -> Result<(), String> {
    if !app.state::<AppState>().protected {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        use objc2::MainThreadMarker;
        use objc2_app_kit::{NSAccessibility, NSApplication, NSView};
        use objc2_foundation::NSArray;
        /// 뷰와 하위 뷰의 접근성 노출을 재귀 깊이 상한 안에서 차단한다.
        fn hide(view: &NSView, depth: usize) {
            view.setAccessibilityHidden(true);
            view.setAccessibilityElement(false);
            // 빈 배열은 접근성 객체 형식 요건을 만족하고 setter가 복사해 보관한다.
            unsafe { view.setAccessibilityChildren(Some(&NSArray::new())) };
            if depth < 32 {
                for child in view.subviews() {
                    hide(&child, depth + 1);
                }
            }
        }
        let marker = MainThreadMarker::new().ok_or(RESTRICTED)?;
        for window in NSApplication::sharedApplication(marker).windows() {
            // WebKit의 별도 접근성 트리가 나중에 생성되어도 창 경계에서 본문 탐색을 차단한다.
            // 빈 배열이므로 잘못된 Objective-C 객체가 전달되지 않으며 배열은 setter가 복사한다.
            unsafe { window.setAccessibilityChildren(Some(&NSArray::new())) };
            if let Some(view) = window.contentView() {
                hide(&view, 0);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tauri가 index.html을 축약한 빈 경로는 허용하고 외부·다른 페이지는 차단하는지 검사한다.
    #[test]
    fn navigation_allows_tauri_initial_document_only() {
        for value in [
            "tauri://localhost",
            "tauri://localhost/",
            "tauri://localhost/index.html",
        ] {
            assert!(
                allows_navigation(&tauri::Url::parse(value).unwrap()),
                "{value}"
            );
        }
        for value in [
            "https://localhost/",
            "https://example.com/",
            "tauri://external/",
            "tauri://localhost/other.html",
            "file:///tmp/document.hwpx",
            "about:blank",
            "tauri://user@localhost/",
            "tauri://localhost:80/",
            "tauri://localhost/?target=external",
            "tauri://localhost/#external",
        ] {
            assert!(
                !allows_navigation(&tauri::Url::parse(value).unwrap()),
                "{value}"
            );
        }
    }

    /// 보호 창에서 기존 평문·본문 조회·창 생성 명령을 직접 호출해도 거부하는지 검사한다.
    #[test]
    fn output_and_plaintext_commands_are_not_allowed() {
        for command in [
            "prepare_staged_hwp_save",
            "commit_staged_hwp_save",
            "export_pdf",
            "export_pdf_from_hwp_path",
            "print_webview",
            "render_document_preview",
            "query_document",
            "mutate_document",
            "create_editor_window",
            "record_recent_document",
            "start_update_install",
        ] {
            assert!(!allows_command(command), "{command}");
        }
        assert!(allows_command("save_managed_document"));
        assert!(allows_command("close_document"));
    }

    /// 보호 창의 권한에 파일·저장소·새 WebView가 없고 일반 창 패턴과 분리되는지 검사한다.
    #[test]
    fn protected_capability_excludes_persistence_and_window_creation() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/managed.json")).unwrap();
        assert_eq!(capability["windows"], serde_json::json!(["managed"]));
        for permission in capability["permissions"].as_array().unwrap() {
            let value = permission.as_str().unwrap();
            assert!(![
                "fs:",
                "store:",
                "log:",
                "updater:",
                "window-state:",
                "core:webview:"
            ]
            .iter()
            .any(|prefix| value.starts_with(prefix)));
            assert_ne!(value, "core:default");
        }
        let ordinary: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        assert_eq!(ordinary["windows"], serde_json::json!(["main", "main*"]));
    }
}
