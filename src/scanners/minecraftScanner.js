'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { ENV, psJson } = require('../utils');
const { findSignaturesIn } = require('../matcher');
const { CONFIG_EXTENSIONS } = require('../signatures');

async function readdirSafe(dir) {
  try {
    return await fs.promises.readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

async function isMinecraftDir(dir) {
  const entries = await readdirSafe(dir);
  const names = entries.map((e) => e.name.toLowerCase());
  return names.includes('versions') || names.includes('mods') || names.includes('options.txt') || names.includes('saves');
}

async function runningGameDirs() {
  const processes = await psJson(`
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match '^(java|javaw|Minecraft|Minecraft.Windows)(\\.exe)?$' -or $_.CommandLine -match '(?i)minecraft|fabric-loader|forge' } |
      Select-Object CommandLine | ConvertTo-Json -Compress
  `);
  const dirs = [];
  for (const process of processes || []) {
    const commandLine = String(process.CommandLine || '');
    const match = commandLine.match(/(?:--gameDir|--game-dir)(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s]+))/i);
    const gameDir = match && (match[1] || match[2] || match[3]);
    if (gameDir) dirs.push(path.normalize(gameDir));
  }
  return dirs;
}

async function findMinecraftDirs() {
  const candidates = new Set();
  const appdata = ENV.APPDATA;
  if (!appdata) return [];

  const fixed = [
    path.join(appdata, '.minecraft'),
    path.join(appdata, '.tlauncher', 'minecraft'),
    path.join(appdata, '.tlauncher', 'legacy', 'Minecraft', 'game'),
    path.join(appdata, '.tlauncher', 'legacy', 'Minecraft', 'game', '.minecraft'),
  ];
  for (const p of fixed) {
    if (await isMinecraftDir(p)) candidates.add(p);
  }

  const launcherInstanceRoots = [
    path.join(appdata, 'PolyMC', 'instances'),
    path.join(appdata, 'PrismLauncher', 'instances'),
    path.join(appdata, 'MultiMC', 'instances'),
    path.join(appdata, '.MultiMC', 'instances'),
  ];
  for (const root of launcherInstanceRoots) {
    const entries = await readdirSafe(root);
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      for (const sub of ['.minecraft', 'minecraft']) {
        const p = path.join(root, e.name, sub);
        if (await isMinecraftDir(p)) candidates.add(p);
      }
    }
  }

  for (const runningDir of await runningGameDirs()) {
    if (await isMinecraftDir(runningDir)) candidates.add(runningDir);
  }

const topEntries = await readdirSafe(appdata);
  for (const e of topEntries) {
    if (!e.isDirectory()) continue;
    const p = path.join(appdata, e.name);
    if (candidates.has(p)) continue;
    if (await isMinecraftDir(p)) candidates.add(p);
  }

  return [...candidates];
}

function zipEntryData(buffer, centralEntryOffset) {
  if (buffer.readUInt32LE(centralEntryOffset) !== 0x02014b50) return null;
  const compression = buffer.readUInt16LE(centralEntryOffset + 10);
  const compressedSize = buffer.readUInt32LE(centralEntryOffset + 20);
  const fileNameLength = buffer.readUInt16LE(centralEntryOffset + 28);
  const extraLength = buffer.readUInt16LE(centralEntryOffset + 30);
  const localOffset = buffer.readUInt32LE(centralEntryOffset + 42);
  if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== 0x04034b50) return null;
  const localNameLength = buffer.readUInt16LE(localOffset + 26);
  const localExtraLength = buffer.readUInt16LE(localOffset + 28);
  const dataStart = localOffset + 30 + localNameLength + localExtraLength;
  const dataEnd = dataStart + compressedSize;
  if (dataEnd > buffer.length) return null;
  const compressed = buffer.subarray(dataStart, dataEnd);
  try {
    if (compression === 0) return compressed;
    if (compression === 8) return zlib.inflateRawSync(compressed, { maxOutputLength: 4 * 1024 * 1024 });
  } catch {
    return null;
  }
  return null;
}

async function scanJarMetadata(jarPath, findings) {
  let buffer;
  try {
    const stat = await fs.promises.stat(jarPath);
    if (stat.size > 64 * 1024 * 1024) return;
    buffer = await fs.promises.readFile(jarPath);
  } catch {
    return;
  }
  const start = Math.max(0, buffer.length - 0xffff - 22);
  let eocd = -1;
  for (let i = Math.max(0, buffer.length - 22); i >= start; i--) {
    if (buffer.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return;
  const entryCount = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  const centralOffset = buffer.readUInt32LE(eocd + 16);
  if (centralOffset + centralSize > buffer.length) return;

  let offset = centralOffset;
  for (let i = 0; i < entryCount && offset + 46 <= buffer.length; i++) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) break;
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString('utf8');
    const nameMatches = findSignaturesIn(name);
    pushMatches(findings, nameMatches, 'minecraft_mod', `Внутри мода найдено имя "${name}" (${path.basename(jarPath)})`, jarPath, 'high');

    const lower = name.toLowerCase();
    if (lower.endsWith('fabric.mod.json') || lower.endsWith('quilt.mod.json') || lower.endsWith('mcmod.info') || lower.endsWith('mods.toml') || lower.endsWith('manifest.mf')) {
      const data = zipEntryData(buffer, offset);
      if (data) {
        const metadataMatches = findSignaturesIn(data.toString('utf8'));
        pushMatches(findings, metadataMatches, 'minecraft_mod', `В метаданных мода найдено совпадение (${path.basename(jarPath)}: ${name})`, jarPath, 'high');
      }
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
}

function pushMatches(findings, matches, evidenceType, detail, filePath, weightHint) {
  for (const sig of matches) {
    findings.push({
      signature: sig.name,
      category: sig.category,
      distinctive: sig.distinctive,
      evidenceType,
      detail,
      path: filePath,
      scanner: 'minecraft',
      weightHint,
    });
  }
}

async function scanOneMinecraftDir(mcDir, findings) {
  
  const modsDir = path.join(mcDir, 'mods');
  for (const e of await readdirSafe(modsDir)) {
    if (!e.isFile()) continue;
    const matches = findSignaturesIn(e.name);
    pushMatches(
      findings, matches, 'minecraft_mod',
      `Файл в папке mods (${mcDir}): "${e.name}" — модификации с таким именем являются известными чит-клиентами/лоадерами`,
      path.join(modsDir, e.name), 'high'
    );
    if (path.extname(e.name).toLowerCase() === '.jar') {
      await scanJarMetadata(path.join(modsDir, e.name), findings);
    }
  }

const versionsDir = path.join(mcDir, 'versions');
  for (const e of await readdirSafe(versionsDir)) {
    if (!e.isDirectory()) continue;
    const matches = findSignaturesIn(e.name);
    pushMatches(
      findings, matches, 'minecraft_version',
      `Установлена версия/сборка клиента с именем "${e.name}" в ${versionsDir} — типичное название для кастомного чит-клиента`,
      path.join(versionsDir, e.name), 'high'
    );
    
    for (const inner of await readdirSafe(path.join(versionsDir, e.name))) {
      const innerMatches = findSignaturesIn(inner.name);
      pushMatches(
        findings, innerMatches, 'minecraft_version_file',
        `Файл кастомной сборки клиента: "${inner.name}" (${e.name})`,
        path.join(versionsDir, e.name, inner.name), 'high'
      );
    }
  }

for (const e of await readdirSafe(mcDir)) {
    const lower = e.name.toLowerCase();
    const standard = ['mods', 'versions', 'saves', 'resourcepacks', 'shaderpacks', 'logs', 'crash-reports',
      'config', 'assets', 'libraries', 'options.txt', 'servers.dat', 'launcher_profiles.json', 'screenshots', 'texturepacks'];
    if (standard.includes(lower)) continue;

    const matches = findSignaturesIn(e.name);
    pushMatches(
      findings, matches, 'minecraft_root_folder',
      `Нестандартный файл/папка в корне ${mcDir}: "${e.name}" — совпадает с именем известного чит-клиента`,
      path.join(mcDir, e.name), 'medium'
    );

    const ext = path.extname(lower);
    if (CONFIG_EXTENSIONS.includes(ext)) {
      findings.push({
        signature: ext,
        category: 'configExt',
        distinctive: true,
        evidenceType: 'minecraft_config_ext',
        detail: `В корне ${mcDir} найден конфиг-файл "${e.name}" — расширение ${ext} используется конфигами читерских клиентов (Wexide/Impact и аналоги)`,
        path: path.join(mcDir, e.name),
        scanner: 'minecraft',
        weightHint: 'medium',
      });
    }
  }

for (const e of await readdirSafe(path.join(mcDir, 'config'))) {
    const matches = findSignaturesIn(e.name);
    pushMatches(
      findings, matches, 'minecraft_config_folder',
      `В папке config найден файл/папка "${e.name}", совпадающий с именем чит-клиента`,
      path.join(mcDir, 'config', e.name), 'medium'
    );
  }

try {
    const optionsText = await fs.promises.readFile(path.join(mcDir, 'options.txt'), 'utf8');
    const matches = findSignaturesIn(optionsText);
    pushMatches(
      findings, matches, 'minecraft_options',
      `В options.txt встречается упоминание "${matches.map((m) => m.name).join(', ')}" — похоже на сохранённый бинд читерской функции`,
      path.join(mcDir, 'options.txt'), 'low'
    );
  } catch {
    
  }

try {
    const logText = await fs.promises.readFile(path.join(mcDir, 'logs', 'latest.log'), 'utf8');
    const matches = findSignaturesIn(logText);
    for (const sig of matches) {
      findings.push({
        signature: sig.name,
        category: sig.category,
        distinctive: sig.distinctive,
        evidenceType: 'minecraft_log',
        detail: `В игровом логе (logs/latest.log) встречается упоминание "${sig.name}" — клиент мог вывести это в консоль/чат при запуске или переключении читерской функции`,
        path: path.join(mcDir, 'logs', 'latest.log'),
        scanner: 'minecraft',
        weightHint: 'very_high',
      });
    }
  } catch {
    
  }
}

module.exports = {
  id: 'minecraft',
  label: 'Папки Minecraft (mods/versions/логи/конфиги)',

  async run() {
    const dirs = await findMinecraftDirs();
    if (dirs.length === 0) {
      return { findings: [], skipped: true, skipReason: 'Не найдена ни одна папка .minecraft на этом компьютере' };
    }
    const findings = [];
    for (const dir of dirs) {
      await scanOneMinecraftDir(dir, findings);
    }
    return { findings, skipped: false, meta: { minecraftDirsFound: dirs } };
  },
};
