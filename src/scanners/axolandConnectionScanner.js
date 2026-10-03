'use strict';

const fs = require('fs');
const path = require('path');
const { ENV } = require('../utils');
const { findSignaturesIn } = require('../matcher');

const CONNECTION_WORDS = /connect(?:ing|ed)?|join(?:ed|ing)?|server|handshake|login|disconnect/i;
const AXOLAND_WORD = /axoland/i;

async function readText(file) {
  try {
    const stat = await fs.promises.stat(file);
    if (!stat.isFile() || stat.size > 16 * 1024 * 1024) return null;
    return await fs.promises.readFile(file, 'utf8');
  } catch {
    return null;
  }
}

async function collectLogs() {
  const roots = [
    path.join(ENV.APPDATA, '.minecraft'),
    path.join(ENV.APPDATA, '.tlauncher', 'minecraft'),
  ];
  const files = [];
  for (const root of roots) {
    for (const relative of ['logs/latest.log', 'logs/debug.log', 'logs', 'crash-reports']) {
      const target = path.join(root, relative);
      try {
        const stat = await fs.promises.stat(target);
        if (stat.isFile()) files.push(target);
        else if (stat.isDirectory()) {
          const entries = await fs.promises.readdir(target, { withFileTypes: true });
          for (const entry of entries.slice(0, 40)) {
            if (entry.isFile() && /\.(log|txt|json)$/i.test(entry.name)) files.push(path.join(target, entry.name));
          }
        }
      } catch {  }
    }
  }
  return [...new Set(files)];
}

module.exports = {
  id: 'axoland_connection',
  label: 'Подключения к Axoland в логах',

  async run() {
    const findings = [];
    const connectionFiles = new Set();
    for (const file of await collectLogs()) {
      const text = await readText(file);
      if (!text) continue;
      const connectionLines = text.split(/\r?\n/).filter((line) => AXOLAND_WORD.test(line) && CONNECTION_WORDS.test(line));
      if (connectionLines.length === 0) continue;
      connectionFiles.add(file);
      const clientsInLog = findSignaturesIn(text).filter((sig) => sig.category !== 'server_connection');
      for (const sig of clientsInLog) {
        findings.push({
          signature: sig.name,
          category: sig.category,
          distinctive: sig.distinctive,
          evidenceType: 'axoland_usage',
          detail: `В этом логе есть и сигнатура "${sig.name}", и запись подключения к Axoland — возможное использование клиента на Axoland.`,
          path: file,
          scanner: this.id,
        });
      }
      for (const line of text.split(/\r?\n/)) {
        if (!AXOLAND_WORD.test(line) || !CONNECTION_WORDS.test(line)) continue;
        findings.push({
          signature: 'axoland',
          category: 'server_connection',
          distinctive: true,
          evidenceType: 'minecraft_log',
          detail: `В логе Minecraft найдена строка с Axoland в контексте подключения/сервера: ${line.slice(0, 240)}`,
          path: file,
          scanner: this.id,
        });
      }
    }
    return { findings, skipped: false, meta: { connectionFiles: [...connectionFiles] } };
  },
};
