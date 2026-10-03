'use strict';

const fs = require('fs');
const path = require('path');
const { ENV, walkDir, existsSafe } = require('../utils');
const { findSignaturesIn } = require('../matcher');
const { INTERESTING_EXTENSIONS } = require('../signatures');

function getDriveRoots() {
  const roots = [];
  for (let code = 67; code <= 90; code++) { 
    const drive = `${String.fromCharCode(code)}:\\`;
    if (existsSafe(drive)) roots.push(drive);
  }
  return roots;
}

module.exports = {
  id: 'filesystem',
  label: 'Поиск по диску (Desktop/Downloads/Temp/корни дисков)',

  async run() {
    const targets = [
      { dir: path.join(ENV.USERPROFILE, 'Desktop'), depth: 4 },
      { dir: path.join(ENV.USERPROFILE, 'Downloads'), depth: 4 },
      { dir: path.join(ENV.USERPROFILE, 'Documents'), depth: 3 },
      { dir: path.join(ENV.LOCALAPPDATA, 'Temp'), depth: 3 },
      { dir: 'C:\\Program Files', depth: 2 },
      { dir: 'C:\\Program Files (x86)', depth: 2 },
    ];
    for (const root of getDriveRoots()) {
      targets.push({ dir: root, depth: 1 }); 
    }

    const findings = [];
    const seen = new Set();
    let scannedAny = false;

    for (const { dir, depth } of targets) {
      const visited = await walkDir(dir, {
        maxDepth: depth,
        maxEntries: 15000,
        timeBudgetMs: 20000,
        onEntry: (fullPath, entry) => {
          const name = entry.name;
          const ext = path.extname(name).toLowerCase();
          const isInteresting = entry.isDirectory() || INTERESTING_EXTENSIONS.includes(ext);
          if (!isInteresting) return;

          const matches = findSignaturesIn(name);
          for (const sig of matches) {
            const key = sig.name + '|' + fullPath;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push({
              signature: sig.name,
              category: sig.category,
              distinctive: sig.distinctive,
              evidenceType: entry.isDirectory() ? 'filesystem_folder' : 'filesystem_file',
              detail: `${entry.isDirectory() ? 'Папка' : 'Файл'} "${name}" найден(а) в ${dir}`,
              path: fullPath,
              scanner: this.id,
            });
          }
        },
      });
      if (visited > 0) scannedAny = true;
    }

    if (!scannedAny) {
      return { findings: [], skipped: true, skipReason: 'Ни одна из целевых папок не оказалась доступна' };
    }
    return { findings, skipped: false };
  },
};
