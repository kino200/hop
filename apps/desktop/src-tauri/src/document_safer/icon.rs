// 암호문 내용을 바꾸지 않고 원본 문서 도형과 잠금 배지를 Finder 사용자 아이콘에 기록한다.
use std::io::{self, Read};
use std::path::Path;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_app_kit::{NSBezierPath, NSColor, NSImage, NSWorkspace, NSWorkspaceIconCreationOptions};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

/// 암호문 경로를 받아 헤더를 확인한 뒤 표시 메타데이터만 갱신한다. 일반 파일·경로·권한 오류는 반환한다.
pub(super) fn refresh(path: &Path) -> io::Result<()> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::other("An encrypted regular file is required."));
    }
    let mut header = [0; b"<DOCUMENTSAFER_0>".len()];
    std::fs::File::open(path)?.read_exact(&mut header)?;
    if header != *b"<DOCUMENTSAFER_0>" {
        return Err(io::Error::other(
            "The file is not DocumentSafer ciphertext.",
        ));
    }
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::other("The icon path must be Unicode."))?;
    if !NSWorkspace::sharedWorkspace().setIcon_forFile_options(
        Some(&lock_icon()),
        &NSString::from_str(path),
        NSWorkspaceIconCreationOptions::empty(),
    ) {
        return Err(io::Error::other(
            "macOS could not update the encrypted document icon.",
        ));
    }
    Ok(())
}

/// 인자 없이 직접 그린 문서와 빨간 잠금 배지 이미지를 반환한다. 타사 앱 아이콘이나 문서 본문을 읽지 않는다.
fn lock_icon() -> Retained<NSImage> {
    let draw = RcBlock::new(|_: NSRect| {
        let paper = NSBezierPath::bezierPath();
        paper.moveToPoint(NSPoint::new(56.0, 20.0));
        for (x, y) in [(200.0, 20.0), (200.0, 188.0), (152.0, 236.0), (56.0, 236.0)] {
            paper.lineToPoint(NSPoint::new(x, y));
        }
        paper.closePath();
        NSColor::whiteColor().setFill();
        paper.fill();
        NSColor::grayColor().setStroke();
        paper.setLineWidth(4.0);
        paper.stroke();
        let lines = NSBezierPath::bezierPath();
        lines.moveToPoint(NSPoint::new(152.0, 236.0));
        lines.lineToPoint(NSPoint::new(152.0, 188.0));
        lines.lineToPoint(NSPoint::new(200.0, 188.0));
        for y in [160.0, 138.0, 116.0] {
            lines.moveToPoint(NSPoint::new(82.0, y));
            lines.lineToPoint(NSPoint::new(174.0, y));
        }
        lines.setLineWidth(4.0);
        lines.stroke();
        NSColor::systemRedColor().setFill();
        NSBezierPath::bezierPathWithOvalInRect(NSRect::new(
            NSPoint::new(4.0, 4.0),
            NSSize::new(96.0, 96.0),
        ))
        .fill();
        NSColor::whiteColor().setStroke();
        let shackle = NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(
            NSRect::new(NSPoint::new(36.0, 42.0), NSSize::new(32.0, 38.0)),
            14.0,
            14.0,
        );
        shackle.setLineWidth(8.0);
        shackle.stroke();
        NSColor::whiteColor().setFill();
        NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(
            NSRect::new(NSPoint::new(30.0, 26.0), NSSize::new(44.0, 32.0)),
            4.0,
            4.0,
        )
        .fill();
        Bool::YES
    });
    NSImage::imageWithSize_flipped_drawingHandler(NSSize::new(256.0, 256.0), false, &draw)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 파일 경로의 Finder 사용자 아이콘 플래그와 리소스 포크 존재 여부를 반환한다.
    fn has_icon(path: &Path) -> bool {
        let info = std::process::Command::new("/usr/bin/xattr")
            .args(["-px", "com.apple.FinderInfo"])
            .arg(path)
            .output()
            .unwrap();
        let resource = std::process::Command::new("/usr/bin/xattr")
            .args(["-px", "com.apple.ResourceFork"])
            .arg(path)
            .output()
            .unwrap();
        let bytes: Vec<_> = String::from_utf8_lossy(&info.stdout)
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect();
        info.status.success()
            && bytes.get(8).is_some_and(|flags| flags & 4 != 0)
            && resource.status.success()
            && !resource.stdout.is_empty()
    }

    /// 새 파일·원자 교체 후 배지가 기록되고 암호문 바이트는 유지되며 평문·링크는 거부되는지 검사한다.
    #[test]
    fn encrypted_icon_survives_atomic_replacement_without_changing_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted.hwpx");
        for body in [
            b"<DOCUMENTSAFER_0>first".as_slice(),
            b"<DOCUMENTSAFER_0>second".as_slice(),
        ] {
            let temporary = dir.path().join("replacement.tmp");
            std::fs::write(&temporary, body).unwrap();
            std::fs::rename(&temporary, &path).unwrap();
            assert!(!has_icon(&path));
            refresh(&path).unwrap();
            assert!(has_icon(&path));
            assert_eq!(std::fs::read(&path).unwrap(), body);
        }
        let plain = dir.path().join("plain.hwpx");
        std::fs::write(&plain, b"PK\x03\x04plain document without DRM header").unwrap();
        assert!(refresh(&plain).is_err());
        assert!(!has_icon(&plain));
        let link = dir.path().join("link.hwpx");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(refresh(&link).is_err());
        assert!(refresh(dir.path()).is_err());
    }

    /// 명시한 외부 시험 암호문의 배지 메타데이터만 복원하고 본문 바이트 보존을 검증한다.
    #[test]
    #[ignore = "requires HOP_BADGE_TEST_FILE pointing to an authorized encrypted fixture"]
    fn supplied_encrypted_fixture_gets_icon_without_content_change() {
        let path = std::path::PathBuf::from(std::env::var_os("HOP_BADGE_TEST_FILE").unwrap());
        let original = std::fs::read(&path).unwrap();
        refresh(&path).unwrap();
        assert!(has_icon(&path));
        assert!(std::fs::read(&path).unwrap() == original);
    }
}
