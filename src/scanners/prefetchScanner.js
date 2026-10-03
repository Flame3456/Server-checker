'use strict';

const fs = require('fs');
const path = require('path');
const { ENV } = require('../utils');
const { findSignaturesIn } = require('../matcher');

module.exports = {
  id: 'prefetch',
  label: 'Prefetch (история запуска программ)',

  async run() {
    const dir = path.join(ENV.SYSTEMROOT, 'Prefetch');
    let files;
    try {
      files = await fs.promises.readdir(dir);
    } catch {
      return {
        findings: [],
        skipped: true,
        skipReason: 'Папка Prefetch недоступна (обычно требует запуска от имени администратора)',
      };
    }

    const findings = [];
    for (const f of files) {
      if (!f.toLowerCase().endsWith('.pf')) continue;
      const matches = findSignaturesIn(f);
      for (const sig of matches) {
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'prefetch',
          detail: `Prefetch-запись "${f}" — программа с таким именем ранее запускалась на этом компьютере (даже если сейчас уже удалена)`,
          path: path.join(dir, f),
          scanner: this.id,
        });
      }
    }
    return { findings, skipped: false };
  },
};
