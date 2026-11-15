// Keep HOP clipboard commands insulated from rhwp-studio's internal module layout.
import {
  prepareRhwpInternalClipboardHtml,
  writeTextHtmlToClipboard as writeUpstreamTextHtmlToClipboard,
} from '@upstream/engine/input-handler-keyboard';
import { isProtectedDocument, PROTECTED_MESSAGE } from '../core/protected-document';

export { prepareRhwpInternalClipboardHtml };

/**
 * 일반 문서의 텍스트·HTML을 클립보드에 기록하고 완료를 반환한다.
 * 보호 문서는 반출을 거부하며 일반 WebView의 서식 기록 실패 시 텍스트로 대체한다.
 */
export async function writeTextHtmlToClipboard(text: string, html: string): Promise<void> {
  if (isProtectedDocument()) throw new Error(PROTECTED_MESSAGE);
  try {
    await writeUpstreamTextHtmlToClipboard(text, html);
  } catch (richClipboardError) {
    const clipboard = globalThis.navigator?.clipboard;
    const writeText = clipboard?.writeText;
    if (!writeText) throw richClipboardError;
    await writeText.call(clipboard, text);
  }
}
