'use strict';

const { psJson } = require('../utils');
const { findSignaturesIn } = require('../matcher');

module.exports = {
  id: 'processes',
  label: 'Запущенные процессы',

  async run() {
    const list = await psJson('Get-Process | Select-Object Name,Path,Id | ConvertTo-Json -Compress');
    if (!list) {
      return { findings: [], skipped: true, skipReason: 'Не удалось получить список процессов (PowerShell недоступен)' };
    }

    const findings = [];
    for (const proc of list) {
      const combined = `${proc.Name || ''} ${proc.Path || ''}`;
      const matches = findSignaturesIn(combined);
      for (const sig of matches) {
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'process',
          detail: `Процесс "${proc.Name}" (PID ${proc.Id}) сейчас запущен${proc.Path ? ` — ${proc.Path}` : ''}`,
          path: proc.Path || null,
          scanner: this.id,
        });
      }
    }
    return { findings, skipped: false };
  },
};
