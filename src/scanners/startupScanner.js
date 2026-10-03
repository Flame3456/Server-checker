'use strict';

const fs = require('fs');
const path = require('path');
const { psJson, ENV } = require('../utils');
const { findSignaturesIn } = require('../matcher');

const CMD = `
$paths = @(
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
);
$out = @();
foreach ($p in $paths) {
  try {
    $props = Get-ItemProperty -Path $p -ErrorAction Stop;
    foreach ($prop in $props.PSObject.Properties) {
      if ($prop.Name -notmatch '^PS') {
        $out += [PSCustomObject]@{ Key = $p; Name = $prop.Name; Value = [string]$prop.Value }
      }
    }
  } catch {}
}
$out | ConvertTo-Json -Compress
`.replace(/\r?\n/g, ' ');

module.exports = {
  id: 'startup',
  label: 'Автозапуск (реестр + папка Startup)',

  async run() {
    const findings = [];
    let anySuccess = false;

    const regEntries = await psJson(CMD, { timeoutMs: 15000 });
    if (regEntries) {
      anySuccess = true;
      for (const entry of regEntries) {
        const combined = `${entry.Name || ''} ${entry.Value || ''}`;
        const matches = findSignaturesIn(combined);
        for (const sig of matches) {
          findings.push({
            signature: sig.name,
            category: sig.category,
            distinctive: sig.distinctive,
            evidenceType: 'startup_registry',
            detail: `Автозапуск через реестр (${entry.Key}): "${entry.Name}" = "${entry.Value}"`,
            path: entry.Value || null,
            scanner: this.id,
          });
        }
      }
    }

    const startupDir = path.join(ENV.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
    try {
      const files = await fs.promises.readdir(startupDir);
      anySuccess = true;
      for (const f of files) {
        const matches = findSignaturesIn(f);
        for (const sig of matches) {
          findings.push({
            signature: sig.name,
            category: sig.category,
            distinctive: sig.distinctive,
            evidenceType: 'startup_folder',
            detail: `Ярлык автозапуска в папке Startup: "${f}"`,
            path: path.join(startupDir, f),
            scanner: this.id,
          });
        }
      }
    } catch {
      
    }

    if (!anySuccess) {
      return { findings: [], skipped: true, skipReason: 'Не удалось прочитать автозапуск (реестр и папка Startup недоступны)' };
    }
    return { findings, skipped: false };
  },
};
