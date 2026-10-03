'use strict';

const fs = require('fs');
const path = require('path');
const { ENV } = require('../utils');
const { findSignaturesIn } = require('../matcher');

function extractUtf16Strings(buffer, minLen = 4) {
  const out = [];
  let current = '';
  for (let i = 0; i + 1 < buffer.length; i += 2) {
    const code = buffer.readUInt16LE(i);
    if (code >= 0x20 && code <= 0x7e) {
      current += String.fromCharCode(code);
    } else {
      if (current.length >= minLen) out.push(current);
      current = '';
    }
  }
  if (current.length >= minLen) out.push(current);
  return out;
}

async function scanJumpLists(dir, findings, scannerId) {
  let files;
  try {
    files = await fs.promises.readdir(dir);
  } catch {
    return false;
  }
  for (const f of files) {
    const full = path.join(dir, f);
    let buf;
    try {
      buf = await fs.promises.readFile(full);
    } catch {
      continue;
    }
    const strings = extractUtf16Strings(buf);
    const seen = new Set();
    for (const s of strings) {
      const matches = findSignaturesIn(s);
      for (const sig of matches) {
        const key = sig.name + '|' + f;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'jumplist',
          detail: `Jump List хранит след недавно открывавшегося пути, содержащего "${sig.name}" (запись: "${s.slice(0, 120)}")`,
          path: full,
          scanner: scannerId,
        });
      }
    }
  }
  return true;
}

module.exports = {
  id: 'recent_files',
  label: 'Недавние файлы и Jump Lists',

  async run() {
    const findings = [];
    let anySuccess = false;

const recentDir = path.join(ENV.APPDATA, 'Microsoft', 'Windows', 'Recent');
    try {
      const files = await fs.promises.readdir(recentDir);
      anySuccess = true;
      for (const f of files) {
        const matches = findSignaturesIn(f);
        for (const sig of matches) {
          findings.push({
            signature: sig.name,
            category: sig.category,
            distinctive: sig.distinctive,
            evidenceType: 'recent_file',
            detail: `В списке недавних файлов Windows найден ярлык: "${f}"`,
            path: path.join(recentDir, f),
            scanner: this.id,
          });
        }
      }
    } catch {
      
    }

    const autoDestDir = path.join(recentDir, 'AutomaticDestinations');
    const customDestDir = path.join(recentDir, 'CustomDestinations');
    const okAuto = await scanJumpLists(autoDestDir, findings, this.id);
    const okCustom = await scanJumpLists(customDestDir, findings, this.id);
    anySuccess = anySuccess || okAuto || okCustom;

    if (!anySuccess) {
      return { findings: [], skipped: true, skipReason: 'Папки недавних файлов / Jump Lists недоступны' };
    }
    return { findings, skipped: false };
  },
};
