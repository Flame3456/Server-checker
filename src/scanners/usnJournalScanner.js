'use strict';

const { safeExec } = require('../utils');
const { findSignaturesIn } = require('../matcher');

module.exports = {
  id: 'usn_journal',
  label: 'USN Journal (следы удалённых файлов)',

  async run(ctx) {
    if (!ctx || !ctx.isAdminFlag) {
      return {
        findings: [],
        skipped: true,
        skipReason: 'Требуются права администратора — запустите AXOLAND Checker от имени администратора для этой проверки',
      };
    }

const out = await safeExec('fsutil usn readjournal C: csv', { timeoutMs: 30000, maxBuffer: 64 * 1024 * 1024 });
    if (!out) {
      return { findings: [], skipped: true, skipReason: 'Не удалось прочитать журнал изменений тома C: (журнал может быть не включён)' };
    }

    const findings = [];
    const lines = out.split(/\r?\n/);
    const seen = new Set();
    for (const line of lines) {
      const matches = findSignaturesIn(line);
      for (const sig of matches) {
        const key = sig.name + '|' + line.slice(0, 40);
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'usn_journal',
          detail: `В журнале изменений файловой системы найдена запись о файле, содержащем "${sig.name}" — это может быть след УЖЕ УДАЛЁННОГО файла`,
          path: null,
          recoveryStatus: 'trace_only',
          recoveryPattern: `*${sig.name}*`,
          sourceDrive: 'C:',
          scanner: this.id,
        });
      }
    }
    return { findings, skipped: false };
  },
};
