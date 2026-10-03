'use strict';

const { psJson } = require('../utils');
const { findSignaturesIn } = require('../matcher');

const CMD = `
Get-ItemProperty @(
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
) -ErrorAction SilentlyContinue |
Select-Object DisplayName,InstallLocation,Publisher |
Where-Object { $_.DisplayName } |
ConvertTo-Json -Compress
`.replace(/\r?\n/g, ' ');

module.exports = {
  id: 'installed_programs',
  label: 'Установленные программы',

  async run() {
    const list = await psJson(CMD, { timeoutMs: 25000 });
    if (!list) {
      return { findings: [], skipped: true, skipReason: 'Не удалось прочитать реестр установленных программ' };
    }

    const findings = [];
    for (const app of list) {
      const combined = `${app.DisplayName || ''} ${app.InstallLocation || ''} ${app.Publisher || ''}`;
      const matches = findSignaturesIn(combined);
      for (const sig of matches) {
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'installed_program',
          detail: `В списке установленных программ найдено: "${app.DisplayName}"${app.InstallLocation ? ` (${app.InstallLocation})` : ''}`,
          path: app.InstallLocation || null,
          scanner: this.id,
        });
      }
    }
    return { findings, skipped: false };
  },
};
