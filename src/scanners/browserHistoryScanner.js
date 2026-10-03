'use strict';

const fs = require('fs');
const path = require('path');
const { ENV } = require('../utils');
const { getSignatures } = require('../signatures');

const BROWSER_FILES = [
  path.join(ENV.LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Default', 'History'),
  path.join(ENV.LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data', 'Default', 'History'),
  path.join(ENV.LOCALAPPDATA, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'History'),
  path.join(ENV.APPDATA, 'Opera Software', 'Opera Stable', 'History'),
  path.join(ENV.APPDATA, 'Mozilla', 'Firefox', 'Profiles'),
];

async function collectFiles(root) {
  try {
    const stat = await fs.promises.stat(root);
    if (stat.isFile()) return [root];
    if (!stat.isDirectory()) return [];
  } catch {
    return [];
  }
  const out = [];
  const stack = [root];
  while (stack.length && out.length < 100) {
    const dir = stack.pop();
    let entries;
    try { entries = await fs.promises.readdir(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile() && (entry.name === 'History' || entry.name === 'places.sqlite')) out.push(full);
    }
  }
  return out;
}

module.exports = {
  id: 'browser_history',
  label: 'История браузеров',

  async run() {
    const files = (await Promise.all(BROWSER_FILES.flatMap((file) => collectFiles(file)))).flat();
    if (!files.length) {
      return { findings: [], skipped: true, skipReason: 'Файлы истории браузеров не найдены (либо браузер сейчас открыт и файл заблокирован)' };
    }

    const signatures = getSignatures();
    const findings = [];
    for (const file of files) {
      let text;
      try { text = await fs.promises.readFile(file, 'utf8'); } catch { continue; }
      for (const sig of signatures) {
        const needle = sig.name.toLowerCase();
        const count = text.toLowerCase().split(needle).length - 1;
        if (count <= 0) continue;
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'browser_history',
          detail: `В истории браузера (${file}) встречается упоминание "${sig.name}" (≈${count} совпадений в файле) — это может быть посещение сайта чит-клиента или случайное совпадение текста`,
          path: file,
          scanner: this.id,
        });
      }
    }
    return { findings, skipped: false };
  },
};
