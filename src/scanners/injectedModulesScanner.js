'use strict';

const { psJson } = require('../utils');
const { findSignaturesIn } = require('../matcher');

const CMD = `
$targets = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object {
    $_.Name -match '^(java|javaw|Minecraft|Minecraft.Windows)(\\.exe)?$' -or
    $_.CommandLine -match '(?i)minecraft|net\\.minecraft|fabric-loader|forge'
  };
$out = @();
foreach ($target in $targets) {
  try {
    $p = Get-Process -Id $target.ProcessId -ErrorAction Stop;
    foreach ($m in $p.Modules) {
      $out += [PSCustomObject]@{ Pid = $p.Id; ProcName = $p.ProcessName; ModuleName = $m.ModuleName; FileName = $m.FileName; CommandLine = $target.CommandLine }
    }
  } catch {}
}
$out | ConvertTo-Json -Compress
`.replace(/\r?\n/g, ' ');

module.exports = {
  id: 'injected_modules',
  label: 'Модули, загруженные в процесс Minecraft (DLL-инжекты)',

  async run() {
    const list = await psJson(CMD, { timeoutMs: 20000 });
    if (!list) {
      return {
        findings: [],
        skipped: true,
        skipReason: 'Процесс java/javaw не найден или доступ к его модулям закрыт (Minecraft может быть не запущен)',
      };
    }

    const findings = [];
    for (const mod of list) {
        const combined = `${mod.ModuleName || ''} ${mod.FileName || ''} ${mod.CommandLine || ''}`;
      const matches = findSignaturesIn(combined);
      for (const sig of matches) {
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'injected_module',
          detail: `В процесс Minecraft (${mod.ProcName}, PID ${mod.Pid}) загружен модуль "${mod.ModuleName}"${mod.FileName ? ` — ${mod.FileName}` : ''} — это прямой признак DLL-инжекта чит-клиента`,
          path: mod.FileName || null,
          scanner: this.id,
        });
      }
    }
    return { findings, skipped: false };
  },
};
