// 보호 문서의 화면 명령·클립보드·브라우저 출력 경로를 제한한다.
import type { CommandDef } from '@/upstream/commands';

export const PROTECTED_MESSAGE = '보호 문서는 암호화 HWPX 저장만 허용합니다.';

/** 네이티브 초기화 스크립트가 지정한 보호 창 여부를 반환한다. */
export function isProtectedDocument(): boolean {
  return typeof window !== 'undefined'
    && (window as Window & { __HOP_PROTECTED__?: boolean }).__HOP_PROTECTED__ === true;
}

/** 보호 문서에서 검토한 편집·보기·저장 명령만 허용한다. */
export function allowsProtectedCommand(id: string): boolean {
  if (['file:open', 'file:new-doc', 'file:save', 'file:save-as',
    'edit:undo', 'edit:redo', 'edit:select-all', 'edit:find', 'edit:replace',
    'edit:delete', 'edit:paste', 'edit:format-copy'].includes(id)) return true;
  return /^(format:|page:|view:zoom|view:ctrl-mark$|view:para-mark$)/.test(id)
    || /^(table:|insert:)/.test(id) && !/copy|paste|image|chart|field/.test(id);
}

/** 명령의 활성 상태와 실행 양쪽에서 보호 정책을 적용한 복사본을 반환한다. */
export function protectCommand(command: CommandDef): CommandDef {
  return {
    ...command,
    canExecute: (ctx) => (!isProtectedDocument() || allowsProtectedCommand(command.id))
      && (command.canExecute?.(ctx) ?? true),
    execute: (services, params) => {
      if (isProtectedDocument() && !allowsProtectedCommand(command.id)) throw new Error(PROTECTED_MESSAGE);
      return command.execute(services, params);
    },
  };
}

/** 네이티브 경계에 더해 사용자 복사·드래그·인쇄와 브라우저 저장 API를 차단한다. */
export function installProtectedDocumentGuards(): void {
  if (!isProtectedDocument()) return;
  const deny = (): never => { throw new Error(PROTECTED_MESSAGE); };
  const stop = (event: Event): void => { event.preventDefault(); event.stopImmediatePropagation(); };
  for (const type of ['copy', 'cut', 'dragstart', 'drop', 'contextmenu']) document.addEventListener(type, stop, true);
  document.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && ['c', 'x', 'p'].includes(event.key.toLowerCase())) stop(event);
  }, true);
  window.print = deny;
  window.open = deny;
  if (navigator.clipboard) {
    Object.defineProperties(navigator.clipboard, { write: { value: deny }, writeText: { value: deny } });
  }
  document.addEventListener('click', (event) => {
    if ((event.target as Element | null)?.closest?.('a[href], a[download]')) stop(event);
  }, true);
  // 비영속 WebView라도 문서 복구 플러그인이 저장 경로를 새로 추가하지 못하게 한다.
  Storage.prototype.setItem = deny;
  if (typeof indexedDB !== 'undefined') Object.defineProperty(indexedDB, 'open', { value: deny });
  // WASM 또는 상위 편집기의 진단 문자열에도 본문이 섞일 수 있어 보호 창에서는 출력하지 않는다.
  for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const) console[method] = () => {};
}
