'use strict';

const { psJson } = require('../utils');
const { findSignaturesIn } = require('../matcher');

module.exports = {
  id: 'drivers',
  label: 'Драйверы уровня ядра',

  async run() {
    const list = await psJson(
      'Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,PathName,State | ConvertTo-Json -Compress',
      { timeoutMs: 25000 }
    );
    if (!list) {
      return { findings: [], skipped: true, skipReason: 'Не удалось получить список драйверов (нужны права администратора)' };
    }

    const findings = [];
    for (const drv of list) {
      const combined = `${drv.Name || ''} ${drv.DisplayName || ''} ${drv.PathName || ''}`;
      const matches = findSignaturesIn(combined);
      for (const sig of matches) {
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'driver',
          detail: `Загружен драйвер уровня ядра "${drv.DisplayName || drv.Name}" (${drv.State})${drv.PathName ? ` — ${drv.PathName}` : ''} — так маскируются продвинутые чит-клиенты и "призрак"-инжекторы`,
          path: drv.PathName || null,
          scanner: this.id,
        });
      }
    }
    return { findings, skipped: false };
  },
};
