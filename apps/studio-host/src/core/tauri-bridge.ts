import { WasmBridge } from '@/upstream/core';
import type { DocumentInfo } from '@/upstream/core';
import { remove, stat } from '@tauri-apps/plugin-fs';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { isProtectedDocument, PROTECTED_MESSAGE } from './protected-document';
import { finiteFileSize, readFileInChunks, writeFileInChunks } from './chunked-fs';
import { loadDocumentForOpen } from './document-open';

type DocumentFormat = 'hwp' | 'hwpx';

interface NativeOpenResult {
  docId: string;
  fileName: string;
  sourcePath?: string | null;
  format: DocumentFormat;
  pageCount: number;
  revision: number;
  dirty: boolean;
  warnings: unknown[];
}

interface SourceFingerprint {
  len: number;
  modifiedMillis: number;
  contentHash: number;
}

interface ExternalModificationStatus {
  changed: boolean;
  sourcePath?: string | null;
  reason?: string | null;
}

export type DesktopUpdateState =
  | { status: 'idle' }
  | {
      status: 'available';
      version: string;
    }
  | {
      status: 'downloading';
      version: string;
      downloadedBytes: number;
      totalBytes?: number | null;
    }
  | {
      status: 'ready';
      version: string;
    }
  | {
      status: 'error';
      version: string;
      message: string;
    };

export interface DesktopSaveResult {
  docId: string;
  sourcePath?: string | null;
  format: DocumentFormat;
  revision: number;
  dirty: boolean;
  warnings: unknown[];
}

export interface RecentDocument {
  path: string;
  fileName: string;
}

export interface DesktopLoadPayload {
  docInfo: DocumentInfo;
  message: string;
}

export interface DesktopBridgeApi {
  openDocumentFromDialog(): Promise<DesktopLoadPayload | null>;
  openDocumentByPath(path: string): Promise<DesktopLoadPayload | null>;
  takePendingOpenPaths(): Promise<string[]>;
  createNewDocumentAsync(): Promise<DesktopLoadPayload | null>;
  createNewWindow(): Promise<string>;
  saveDocumentFromCommand(): Promise<DesktopSaveResult | null>;
  saveDocumentAsFromCommand(): Promise<DesktopSaveResult | null>;
  exportPdfFromCommand(): Promise<string | null>;
  printCurrentWebview(): Promise<void>;
  destroyCurrentWindow(): Promise<void>;
  cancelAppQuit(): Promise<void>;
  revealInFolder(): Promise<void>;
  listRecentDocuments(): Promise<RecentDocument[]>;
  clearRecentDocuments(): Promise<void>;
  renderDocumentPreview(path: string): Promise<string>;
  getUpdateState(): Promise<DesktopUpdateState>;
  startUpdateInstall(): Promise<void>;
  restartToApplyUpdate(): Promise<void>;
  hasUnsavedChanges(): boolean;
  markDocumentDirty(): void;
  confirmWindowClose(): Promise<boolean>;
}

export class TauriBridge extends WasmBridge implements DesktopBridgeApi {
  private docId: string | null = null;
  private sourcePath: string | null = null;
  private sourceFormat: DocumentFormat = 'hwp';
  private revision = 0;
  private dirty = false;
  private documentOperationPending = false;

  async openDocumentFromDialog(): Promise<DesktopLoadPayload | null> {
    return this.withDocumentOperation(async () => {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({
        multiple: false,
        filters: [{ name: 'HWP/HWPX 문서', extensions: ['hwp', 'hwpx'] }],
      });
      if (!selected || Array.isArray(selected)) return null;
      return this.openDocumentPath(selected);
    });
  }

  async openDocumentByPath(path: string): Promise<DesktopLoadPayload | null> {
    return this.withDocumentOperation(() => this.openDocumentPath(path));
  }

  /** 경로를 먼저 네이티브 보호 경계에서 검사하고 보호 본문은 메모리로만 로드한다. */
  private async openDocumentPath(path: string): Promise<DesktopLoadPayload | null> {
    if (!(await this.confirmReadyForDocumentReplacement())) return null;

    const managed = await this.invoke<{ document?: NativeOpenResult; bytes: number[]; redirected: boolean } | null>(
      'open_managed_document', { path },
    );
    if (managed?.redirected) return null;
    if (managed?.document) return this.loadManagedDocument(managed.document, managed.bytes);
    if (isProtectedDocument()) throw new Error(PROTECTED_MESSAGE);

    await this.invoke<void>('prepare_document_open', { path });
    const { bytes, sourceFingerprint } = await this.readFileForOpen(path);
    const result = await this.invoke<NativeOpenResult>('open_document_tracking', {
      path,
      sourceFingerprint,
    });
    const previousDocId = this.docId;
    try {
      const info = await loadDocumentForOpen(this, bytes, result.fileName);
      if (!info) {
        await this.closeNativeDocument(result.docId);
        return null;
      }
      this.applyNativeOpenResult(result, this.normalizedSourceFormat(super.getSourceFormat()));
      await this.noteFinderRecentDocument(path);
      await this.recordRecentDocument(path);
      await this.closeReplacedDocument(previousDocId, result.docId);
      return {
        docInfo: info,
        message: `${result.fileName} — ${info.pageCount}페이지`,
      };
    } catch (error) {
      await this.closeNativeDocument(result.docId);
      throw error;
    }
  }

  /** 보호 메모리 바이트를 WASM으로 옮기고 전송용 복사본을 지운 뒤 추적 정보를 반영한다. */
  private async loadManagedDocument(result: NativeOpenResult, values: number[]): Promise<DesktopLoadPayload> {
    const bytes = new Uint8Array(values);
    values.fill(0);
    try {
      const info = await loadDocumentForOpen(this, bytes, result.fileName);
      if (!info) throw new Error('보호 HWPX 문서를 열지 못했습니다.');
      this.applyNativeOpenResult(result, 'hwpx');
      return { docInfo: info, message: `${result.fileName} — 보호 문서` };
    } catch (error) {
      await this.closeNativeDocument(result.docId);
      throw error;
    } finally {
      bytes.fill(0);
    }
  }

  async takePendingOpenPaths(): Promise<string[]> {
    return this.invoke<string[]>('take_pending_open_paths');
  }

  async createNewDocumentAsync(): Promise<DesktopLoadPayload | null> {
    return this.withDocumentOperation(() => this.createDocument());
  }

  /** 현재 창의 보호 상태에 맞춰 새 문서를 만들고 네이티브 추적 정보를 반환한다. */
  private async createDocument(): Promise<DesktopLoadPayload | null> {
    if (!(await this.confirmReadyForDocumentReplacement())) return null;

    const result = await this.invoke<NativeOpenResult>(isProtectedDocument() ? 'create_managed_document' : 'create_document');
    const previousDocId = this.docId;
    try {
      const info = super.createNewDocument();
      this.applyNativeOpenResult(result);
      await this.closeReplacedDocument(previousDocId, result.docId);
      return {
        docInfo: info,
        message: `${result.fileName} — ${info.pageCount}페이지`,
      };
    } catch (error) {
      await this.closeNativeDocument(result.docId);
      throw error;
    }
  }

  async createNewWindow(): Promise<string> {
    return this.invoke<string>('create_editor_window');
  }

  getSourceFormat(): string {
    return this.sourceFormat;
  }

  async saveDocumentFromCommand(): Promise<DesktopSaveResult | null> {
    return this.withDocumentOperation(() => this.saveDocument());
  }

  /** 보호 창은 메모리 HWPX 암호화 저장을, 일반 창은 기존 HWP 저장을 수행한다. */
  private async saveDocument(): Promise<DesktopSaveResult | null> {
    const docId = this.ensureDocumentLoaded();
    if (isProtectedDocument()) return this.saveManagedDocument();
    if (this.requiresPasswordForSave) {
      throw new Error('암호 문서의 원본 저장은 아직 지원하지 않습니다. 다른 이름으로 저장에서 암호 없는 HWP 파일로 저장하세요.');
    }
    if (!this.sourcePath) {
      return this.saveDocumentAs();
    }
    if (this.sourceFormat === 'hwpx') {
      throw new Error('HWPX 원본 저장은 아직 안전하게 지원하지 않습니다. 다른 이름으로 저장에서 HWP 파일로 저장하세요.');
    }
    return this.saveHwpThroughStaging(docId, null);
  }

  async saveDocumentAsFromCommand(): Promise<DesktopSaveResult | null> {
    return this.withDocumentOperation(() => this.saveDocumentAs());
  }

  /** 새 보호 문서의 암호화 저장 위치 또는 일반 HWP 저장 위치를 선택한다. */
  private async saveDocumentAs(): Promise<DesktopSaveResult | null> {
    const docId = this.ensureDocumentLoaded();
    if (isProtectedDocument()) {
      if (this.sourcePath) throw new Error('기존 보호 문서는 원본 경로에 암호화 저장해 주세요.');
      return this.saveManagedDocument();
    }
    const targetPath = await this.selectSavePath(this.suggestedHwpName(), 'HWP 문서', ['hwp']);
    if (!targetPath) return null;
    if (this.requiresPasswordForSave) {
      const { message } = await import('@tauri-apps/plugin-dialog');
      const choice = await message('저장한 HWP 파일에는 암호가 적용되지 않습니다. 암호 없이 저장하시겠습니까?', {
        title: '암호 없이 저장', kind: 'warning',
        buttons: { ok: '암호 없이 저장', cancel: '취소' },
      });
      if (choice !== '암호 없이 저장' && choice !== 'Ok') return null;
    }
    return this.saveHwpThroughStaging(docId, this.withExtension(targetPath, 'hwp'));
  }

  /** 손실 보고서가 비어 있는 HWPX만 네이티브 암호화 채널로 보내고 성공 후 상태를 갱신한다. */
  private async saveManagedDocument(): Promise<DesktopSaveResult | null> {
    const docId = this.ensureDocumentLoaded();
    const selected = this.sourcePath ?? await this.selectSavePath(
      this.fileName.replace(/\.(hwp|hwpx)$/i, '') + '.hwpx', '암호화 HWPX 문서', ['hwpx'],
    );
    if (!selected) return null;
    const targetPath = this.withExtension(selected, 'hwpx');
    const artifact = super.exportHwpxWithReport();
    const bytes = Array.from(artifact.bytes);
    try {
      const loss = artifact.contentLoss;
      if (artifact.bytes.byteLength > 64 * 1024 * 1024 || loss.schemaVersion !== 1
        || loss.outputFormat !== 'hwpx' || loss.count !== 0 || loss.losses.length !== 0) {
        throw new Error('HWPX 저장 중 보존되지 않는 내용이 있어 저장을 중단했습니다.');
      }
      const result = await this.invoke<DesktopSaveResult>('save_managed_document', {
        docId, targetPath, revision: this.revision, bytes,
      });
      this.applyNativeSaveResult(result);
      return result;
    } finally {
      artifact.bytes.fill(0);
      bytes.fill(0);
    }
  }

  async exportPdfFromCommand(): Promise<string | null> {
    return this.withDocumentOperation(() => this.exportPdf());
  }

  private async exportPdf(): Promise<string | null> {
    this.ensureDocumentLoaded();
    const targetPath = await this.selectSavePath(this.suggestedPdfName(), 'PDF 문서', ['pdf']);
    if (!targetPath) return null;
    const finalPath = this.withExtension(targetPath, 'pdf');
    const stagedPath = await this.invoke<string>('prepare_staged_hwp_pdf_export', {
      targetPath: finalPath,
    });
    try {
      await this.writeCurrentHwpToPath(stagedPath);
      return await this.invoke<string>('export_pdf_from_hwp_path', {
        stagedPath,
        targetPath: finalPath,
        pageRange: null,
        openAfter: true,
      });
    } finally {
      await remove(stagedPath).catch(() => undefined);
    }
  }

  async printCurrentWebview(): Promise<void> {
    await this.withDocumentOperation(() => this.invoke<void>('print_webview'));
  }

  async destroyCurrentWindow(): Promise<void> {
    await this.invoke<void>('destroy_current_window');
  }

  async cancelAppQuit(): Promise<void> {
    await this.invoke<void>('cancel_app_quit');
  }

  async revealInFolder(): Promise<void> {
    if (!this.sourcePath) return;
    await this.invoke<void>('reveal_in_folder', { path: this.sourcePath });
  }

  /** 인자 없이 최근 목록을 반환한다. 보호 창에서는 문서 경로 기록을 읽지 않는다. */
  async listRecentDocuments(): Promise<RecentDocument[]> {
    if (isProtectedDocument()) return [];
    return this.invoke<RecentDocument[]>('list_recent_documents');
  }

  async clearRecentDocuments(): Promise<void> {
    await this.invoke<void>('clear_recent_documents');
  }

  async renderDocumentPreview(path: string): Promise<string> {
    return this.invoke<string>('render_document_preview', { path });
  }

  /** 인자 없이 업데이트 상태를 반환한다. 보호 창에서는 업데이트 서비스를 사용하지 않는다. */
  async getUpdateState(): Promise<DesktopUpdateState> {
    if (isProtectedDocument()) return { status: 'idle' };
    return this.invoke<DesktopUpdateState>('get_update_state');
  }

  async startUpdateInstall(): Promise<void> {
    await this.invoke<void>('start_update_install');
  }

  async restartToApplyUpdate(): Promise<void> {
    await this.invoke<void>('restart_to_apply_update');
  }

  hasUnsavedChanges(): boolean {
    return Boolean(this.docId && this.dirty);
  }

  markDocumentDirty(): void {
    if (!this.docId || this.dirty) return;
    this.dirty = true;
    void this.invoke<void>('mark_document_dirty', { docId: this.docId }).catch((error: unknown) => {
      console.warn('[TauriBridge] native dirty state update failed:', error);
    });
    this.updateDocumentTitle();
  }

  async confirmWindowClose(): Promise<boolean> {
    if (this.documentOperationPending) return false;
    return this.withDocumentOperation(async () => {
      const canClose = await this.confirmReadyForDocumentReplacement();
      if (canClose) await this.releaseCurrentNativeDocument();
      return canClose;
    });
  }

  // A password or native dialog can stay open while Finder/menu events arrive.
  // Keep each document transaction exclusive; internal safety saves share its lock.
  private async withDocumentOperation<T>(operation: () => Promise<T>): Promise<T> {
    if (this.documentOperationPending) {
      throw new Error('다른 문서 작업이 진행 중입니다. 현재 작업을 완료하거나 취소하세요.');
    }
    this.documentOperationPending = true;
    try {
      return await operation();
    } finally {
      this.documentOperationPending = false;
    }
  }

  private async invoke<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(command, args);
  }

  private async closeNativeDocument(docId: string): Promise<void> {
    try {
      await this.invoke<void>('close_document', { docId });
    } catch (error) {
      console.warn('[TauriBridge] native document cleanup failed:', error);
    }
  }

  private async recordRecentDocument(path: string): Promise<void> {
    await this.invoke<void>('record_recent_document', { path }).catch((error: unknown) => {
      console.warn('[TauriBridge] recent document update failed:', error);
    });
  }

  private async noteFinderRecentDocument(path: string): Promise<void> {
    await this.invoke<void>('note_finder_recent_document', { path }).catch((error: unknown) => {
      console.warn('[TauriBridge] Finder recent document update failed:', error);
    });
  }

  private async closeReplacedDocument(previousDocId: string | null, nextDocId: string): Promise<void> {
    if (previousDocId && previousDocId !== nextDocId) {
      await this.closeNativeDocument(previousDocId);
    }
  }

  private async releaseCurrentNativeDocument(): Promise<void> {
    if (this.docId) {
      await this.closeNativeDocument(this.docId);
    }
    this.docId = null;
    this.sourcePath = null;
    this.dirty = false;
    this.updateDocumentTitle();
  }

  private ensureDocumentLoaded(): string {
    if (!this.docId) throw new Error('문서가 로드되지 않았습니다');
    return this.docId;
  }

  private async selectSavePath(
    defaultPath: string,
    filterName: string,
    extensions: string[],
  ): Promise<string | null> {
    const { save } = await import('@tauri-apps/plugin-dialog');
    return save({
      defaultPath,
      filters: [{ name: filterName, extensions }],
    });
  }

  private async saveHwpThroughStaging(
    docId: string,
    targetPath: string | null,
  ): Promise<DesktopSaveResult | null> {
    const finalPath = targetPath ?? this.sourcePath;
    if (!finalPath) throw new Error('새 문서는 저장 경로가 필요합니다');

    const allowExternalOverwrite = await this.confirmExternalOverwriteIfNeeded(docId, finalPath);
    if (allowExternalOverwrite === null) return null;

    const stagedPath = await this.invoke<string>('prepare_staged_hwp_save', { targetPath: finalPath });
    try {
      await this.writeCurrentHwpToPath(stagedPath);
      const result = await this.invoke<DesktopSaveResult>('commit_staged_hwp_save', {
        docId,
        stagedPath,
        targetPath: finalPath,
        expectedRevision: this.revision,
        allowExternalOverwrite,
      });
      this.applyNativeSaveResult(result);
      this.requiresPasswordForSave = false;
      await this.noteFinderRecentDocument(finalPath);
      return result;
    } finally {
      await remove(stagedPath).catch(() => undefined);
    }
  }

  private async confirmExternalOverwriteIfNeeded(
    docId: string,
    targetPath: string | null,
  ): Promise<boolean | null> {
    const effectivePath = targetPath ?? this.sourcePath;
    const status = await this.invoke<ExternalModificationStatus>('check_external_modification', {
      docId,
      targetPath: effectivePath,
    });
    if (!status.changed) return false;

    const { message } = await import('@tauri-apps/plugin-dialog');
    const overwriteLabel = '덮어쓰기';
    const cancelLabel = '저장 취소';
    const result = await message(
      [
        '원본 파일이 HOP 밖에서 변경되었습니다.',
        status.sourcePath ? `파일: ${status.sourcePath}` : '',
        status.reason ?? '',
        '',
        '그대로 저장하면 외부에서 변경된 내용이 사라질 수 있습니다.',
      ].filter(Boolean).join('\n'),
      {
        title: '외부 변경 감지',
        kind: 'warning',
        buttons: {
          yes: overwriteLabel,
          no: cancelLabel,
          cancel: '취소',
        },
      },
    );

    return result === overwriteLabel || result === 'Yes' ? true : null;
  }

  private async confirmReadyForDocumentReplacement(): Promise<boolean> {
    if (!this.hasUnsavedChanges()) return true;

    const decision = await this.promptUnsavedChanges();
    if (decision === 'cancel') return false;
    if (decision === 'discard') return true;

    try {
      const result = await this.saveCurrentDocumentForSafety();
      return result !== null;
    } catch (error) {
      await this.showError('저장 실패', `문서를 저장하지 못했습니다.\n${error}`);
      return false;
    }
  }

  /** 종료 전 현재 문서를 저장하고 결과를 반환한다. 보호 문서는 같은 암호문 경로를 유지한다. */
  private async saveCurrentDocumentForSafety(): Promise<DesktopSaveResult | null> {
    if (isProtectedDocument()) return this.saveDocument();
    if (this.sourceFormat === 'hwpx' || this.requiresPasswordForSave) {
      return this.saveDocumentAs();
    }
    return this.saveDocument();
  }

  private async promptUnsavedChanges(): Promise<'save' | 'discard' | 'cancel'> {
    const { message } = await import('@tauri-apps/plugin-dialog');
    const saveLabel = '저장';
    const discardLabel = '저장 안 함';
    const result = await message(
      `${this.fileName || '현재 문서'}의 변경 내용을 저장할까요?`,
      {
        title: '저장 확인',
        kind: 'warning',
        buttons: {
          yes: saveLabel,
          no: discardLabel,
          cancel: '취소',
        },
      },
    );

    if (result === saveLabel || result === 'Yes') return 'save';
    if (result === discardLabel || result === 'No') return 'discard';
    return 'cancel';
  }

  private async showError(title: string, text: string): Promise<void> {
    const { message } = await import('@tauri-apps/plugin-dialog');
    await message(text, {
      title,
      kind: 'error',
      buttons: { ok: '확인' },
    });
  }

  private async writeCurrentHwpToPath(path: string): Promise<void> {
    await writeFileInChunks(path, super.exportHwp());
  }

  private withExtension(path: string, extension: string): string {
    const escaped = extension.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`\\.${escaped}$`, 'i').test(path) ? path : `${path}.${extension}`;
  }

  private async readFileForOpen(path: string): Promise<{
    bytes: Uint8Array;
    sourceFingerprint?: SourceFingerprint;
  }> {
    const before = await stat(path);
    const { bytes, contentHash } = await readFileInChunks(path, finiteFileSize(before.size));
    const after = await stat(path);
    const beforeFingerprint = this.statFingerprint(before);
    const afterFingerprint = this.statFingerprint(after);
    if (
      beforeFingerprint &&
      afterFingerprint &&
      (beforeFingerprint.len !== afterFingerprint.len ||
        beforeFingerprint.modifiedMillis !== afterFingerprint.modifiedMillis)
    ) {
      throw new Error('파일을 읽는 중 변경되었습니다. 다시 시도하세요.');
    }
    return {
      bytes,
      sourceFingerprint: afterFingerprint
        ? {
            ...afterFingerprint,
            contentHash,
          }
        : undefined,
    };
  }

  private statFingerprint(
    info: Partial<{
      size: number;
      mtime: Date | null;
    }>,
  ): Pick<SourceFingerprint, 'len' | 'modifiedMillis'> | undefined {
    const size = finiteFileSize(info.size);
    const modifiedMillis = info.mtime instanceof Date ? info.mtime.getTime() : undefined;
    if (size === undefined || modifiedMillis === undefined || !Number.isFinite(modifiedMillis)) {
      return undefined;
    }
    return { len: size, modifiedMillis };
  }

  private normalizedSourceFormat(value: string): DocumentFormat {
    return value === 'hwpx' ? 'hwpx' : 'hwp';
  }

  private applyNativeOpenResult(result: NativeOpenResult, sourceFormat = result.format): void {
    this.docId = result.docId;
    this.sourcePath = result.sourcePath ?? null;
    this.sourceFormat = sourceFormat;
    this.revision = result.revision;
    this.dirty = result.dirty;
    this.fileName = result.fileName;
    this.updateDocumentTitle();
  }

  private applyNativeSaveResult(result: DesktopSaveResult): void {
    this.docId = result.docId;
    this.sourcePath = result.sourcePath ?? null;
    this.sourceFormat = result.format;
    this.revision = result.revision;
    this.dirty = result.dirty;
    if (this.sourcePath) {
      this.fileName = this.sourcePath.split(/[\\/]/).pop() || this.fileName;
    }
    this.updateDocumentTitle();
  }

  private suggestedHwpName(): string {
    const name = this.fileName.replace(/\.(hwp|hwpx)$/i, '') || 'document';
    return `${name}.hwp`;
  }

  private suggestedPdfName(): string {
    const name = this.fileName.replace(/\.(hwp|hwpx)$/i, '') || 'document';
    return `${name}.pdf`;
  }

  private updateDocumentTitle(): void {
    const title = this.docId
      ? `${this.dirty ? '• ' : ''}${this.fileName || '문서'} - HOP`
      : 'HOP';
    document.title = title;
    void getCurrentWindow().setTitle(title).catch(() => {
      console.warn('[TauriBridge] native window title update failed');
    });
  }
}
