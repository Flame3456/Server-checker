'use strict';

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function safeExec(cmd, { timeoutMs = 20000, maxBuffer = 32 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: timeoutMs, maxBuffer, windowsHide: true }, (err, stdout) => {
      if (err) return resolve(null);
      resolve(stdout);
    });
  });
}

async function psJson(command, opts) {
  const wrapped = `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "${command.replace(/"/g, '\\"')}"`;
  const out = await safeExec(wrapped, opts);
  if (!out) return null;
  try {
    const trimmed = out.trim();
    if (!trimmed) return null;
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return null;
  }
}

async function isAdmin() {
  if (process.platform !== 'win32') return false;
  const out = await safeExec('net session', { timeoutMs: 5000 });
  return out !== null;
}

function expandUserPath(...segments) {
  return path.join(...segments);
}

const ENV = {
  APPDATA: process.env.APPDATA || '',
  LOCALAPPDATA: process.env.LOCALAPPDATA || '',
  USERPROFILE: process.env.USERPROFILE || os.homedir(),
  SYSTEMROOT: process.env.SystemRoot || 'C:\\Windows',
};

async function walkDir(rootDir, { maxDepth = 3, maxEntries = 20000, timeBudgetMs = 15000, onEntry }) {
  const start = Date.now();
  let visited = 0;
  const stack = [{ dir: rootDir, depth: 0 }];

  while (stack.length) {
    if (Date.now() - start > timeBudgetMs) break;
    if (visited > maxEntries) break;
    const { dir, depth } = stack.pop();

    let entries;
    try {
      entries = await fs.promises.readdir(dir, { withFileTypes: true });
    } catch {
      continue; 
    }

    for (const entry of entries) {
      if (Date.now() - start > timeBudgetMs) break;
      if (visited > maxEntries) break;
      visited++;
      const full = path.join(dir, entry.name);
      try {
        onEntry(full, entry);
      } catch {
        
      }
      if (entry.isDirectory() && depth < maxDepth) {
        stack.push({ dir: full, depth: depth + 1 });
      }
    }
  }
  return visited;
}

function existsSafe(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

module.exports = { safeExec, psJson, isAdmin, expandUserPath, ENV, walkDir, existsSafe };
