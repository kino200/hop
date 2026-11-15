// 보호 문서의 명령 실행 및 클립보드·저장소 차단을 검증한다.
import { afterEach, expect, it, vi } from 'vitest';
import { allowsProtectedCommand, installProtectedDocumentGuards, protectCommand } from './protected-document';

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('permits document editing but rejects export, copying, printing and unknown commands', () => {
  for (const id of ['file:save', 'file:new-doc', 'format:bold', 'table:create', 'edit:undo']) {
    expect(allowsProtectedCommand(id)).toBe(true);
  }
  for (const id of ['file:print', 'file:export-pdf', 'file:save-as-hwp', 'file:new-window',
    'file:open-recent', 'edit:copy', 'edit:cut', 'table:transpose-copy', 'unknown:action']) {
    expect(allowsProtectedCommand(id)).toBe(false);
  }
});

it('blocks direct execution as well as command availability in protected windows', () => {
  vi.stubGlobal('window', { __HOP_PROTECTED__: true });
  const execute = vi.fn();
  const command = protectCommand({ id: 'file:print', label: 'print', execute });
  expect(command.canExecute?.({} as never)).toBe(false);
  expect(() => command.execute({} as never)).toThrow('암호화 HWPX');
  expect(execute).not.toHaveBeenCalled();
  vi.stubGlobal('window', {});
  command.execute({} as never);
  expect(execute).toHaveBeenCalledOnce();
});

it('guards copy events, browser printing and persistent storage before document loading', () => {
  const listeners = new Map<string, (event: Event) => void>();
  const clipboard = { write: vi.fn(), writeText: vi.fn() };
  class TestStorage { setItem = undefined; }
  vi.stubGlobal('window', { __HOP_PROTECTED__: true });
  vi.stubGlobal('document', { addEventListener: (name: string, callback: (event: Event) => void) => listeners.set(name, callback) });
  vi.stubGlobal('navigator', { clipboard });
  vi.stubGlobal('Storage', TestStorage);
  vi.stubGlobal('indexedDB', { open: vi.fn() });
  vi.stubGlobal('console', { log: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() });
  installProtectedDocumentGuards();
  const event = { preventDefault: vi.fn(), stopImmediatePropagation: vi.fn() };
  listeners.get('copy')?.(event as unknown as Event);
  expect(event.preventDefault).toHaveBeenCalled();
  expect(() => clipboard.writeText()).toThrow('암호화 HWPX');
  expect(() => window.print()).toThrow('암호화 HWPX');
  expect(() => indexedDB.open('recovery')).toThrow('암호화 HWPX');
});
