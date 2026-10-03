'use strict';

const { psJson } = require('../utils');
const { findSignaturesIn } = require('../matcher');

module.exports = {
  id: 'services',
  label: 'Службы Windows',

  async run() {
    const list = await psJson(
      'Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,State | ConvertTo-Json -Compress',
      { timeoutMs: 25000 }
    );
    if (!list) {
      return { findings: [], skipped: true, skipReason: 'Не удалось получить список служб Windows' };
    }

    const findings = [];
    for (const svc of list) {
      const combined = `${svc.Name || ''} ${svc.DisplayName || ''} ${svc.PathName || ''}`;
      const matches = findSignaturesIn(combined);
      for (const sig of matches) {
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'service',
          detail: `Установлена служба Windows "${svc.DisplayName || svc.Name}" (${svc.State})${svc.PathName ? ` — ${svc.PathName}` : ''}`,
          path: svc.PathName || null,
          scanner: this.id,
        });
      }
    }
    return { findings, skipped: false };
  },
};
