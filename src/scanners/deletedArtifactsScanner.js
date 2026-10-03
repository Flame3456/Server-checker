'use strict';

const fs = require('fs');
const path = require('path');
const { ENV } = require('../utils');
const { findSignaturesIn } = require('../matcher');

function decodeRecycleMetadata(buffer) {
  
  if (!buffer || buffer.length < 24) return null;
  try {
    const version = buffer.readBigUInt64LE(0);
    const pathOffset = version >= 2n ? 28 : 24;

const pathLength = version >= 2n && buffer.length >= 28 ? buffer.readUInt32LE(24) : 0;
    const pathBytes = pathLength > 0 && pathOffset + pathLength * 2 <= buffer.length
      ? buffer.subarray(pathOffset, pathOffset + pathLength * 2)
      : buffer.subarray(pathOffset);
    const originalPath = pathBytes.toString('utf16le').replace(/\0+$/, '');
    const size = Number(buffer.readBigUInt64LE(8));
    return originalPath ? { originalPath, size } : null;
  } catch {
    return null;
  }
}

module.exports = {
  id: 'deleted_artifacts',
  label: 'Удалённые файлы и корзина',

  async run() {
    if (process.platform !== 'win32') return { findings: [], skipped: true, skipReason: 'Сканер корзины доступен только в Windows' };
    const findings = [];
    const recycleRoot = path.join(ENV.SYSTEMROOT ? path.parse(ENV.SYSTEMROOT).root : 'C:\\', '$Recycle.Bin');
    let users;
    try { users = await fs.promises.readdir(recycleRoot, { withFileTypes: true }); } catch {
      return { findings: [], skipped: true, skipReason: 'Корзина недоступна' };
    }

    for (const user of users) {
      if (!user.isDirectory()) continue;
      const dir = path.join(recycleRoot, user.name);
      let entries;
      try { entries = await fs.promises.readdir(dir); } catch { continue; }
      for (const name of entries) {
        if (!name.startsWith('$I')) continue;
        const metadataPath = path.join(dir, name);
        const metadata = decodeRecycleMetadata(await fs.promises.readFile(metadataPath).catch(() => null));
        if (!metadata) continue;
        const dataPath = path.join(dir, `$R${name.slice(2)}`);
        const matches = findSignaturesIn(`${metadata.originalPath} ${name}`);
        if (!matches.length) continue;
        for (const sig of matches) {
          findings.push({
            signature: sig.name,
            category: sig.category,
            distinctive: sig.distinctive,
            evidenceType: 'deleted_artifact',
            detail: `В корзине найден удалённый артефакт "${metadata.originalPath}" (${metadata.size} байт). Файл можно восстановить через контекстное меню.`,
            path: dataPath,
            restorePath: metadata.originalPath,
            recoveryStatus: 'available',
            scanner: this.id,
          });
        }
      }
    }
    return { findings, skipped: false };
  },
};
