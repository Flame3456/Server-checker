'use strict';

const { app, BrowserWindow, ipcMain, Menu, shell, clipboard, dialog } = require('electron');
const fs = require('fs');
const { spawn, execFile } = require('child_process');
const path = require('path');
const { isAdmin } = require('./src/utils');
const { buildReport } = require('./src/scoring');
const { setRemoteSignatures } = require('./src/signatures');
const { syncSignatures } = require('./src/remoteConfig');

const scanners = [
  require('./src/scanners/processScanner'),
  require('./src/scanners/installedProgramsScanner'),
  require('./src/scanners/startupScanner'),
  require('./src/scanners/recentFilesScanner'),
  require('./src/scanners/minecraftScanner'),
  require('./src/scanners/browserHistoryScanner'),
  require('./src/scanners/prefetchScanner'),
  require('./src/scanners/usnJournalScanner'),
  require('./src/scanners/filesystemSearchScanner'),
  require('./src/scanners/servicesScanner'),
  require('./src/scanners/driversScanner'),
  require('./src/scanners/injectedModulesScanner'),
  require('./src/scanners/memoryScanner'),
  require('./src/scanners/axolandConnectionScanner'),
  require('./src/scanners/deletedArtifactsScanner'),
];

let mainWindow;
async function syncRemoteSignatures() {
  setRemoteSignatures([]);
  const result = await syncSignatures();
  setRemoteSignatures(result.signatures);
  return result;
}

function createWindow() {
  const appIcon = app.isPackaged
    ? path.join(process.resourcesPath, 'icon.png')
    : path.join(__dirname, 'icon.png');
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 780,
    minWidth: 860,
    minHeight: 600,
    backgroundColor: '#0f0a1a',
    icon: appIcon,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  if (app.isPackaged) lockProductionDevTools(mainWindow.webContents);
}

function lockProductionDevTools(contents) {
  const isDevToolsShortcut = (input) => {
    const key = String(input.key || '').toLowerCase();
    const modifier = input.control || input.meta;
    return key === 'f12'
      || (modifier && input.shift && ['i', 'j', 'c', 'k'].includes(key))
      || (input.control && input.alt && key === 'i');
  };

  contents.on('before-input-event', (event, input) => {
    if (isDevToolsShortcut(input)) event.preventDefault();
  });
  contents.on('devtools-opened', () => setImmediate(() => contents.closeDevTools()));
}

app.whenReady().then(() => {
  createWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.handle('checker:get-platform-info', async () => {
  return { platform: process.platform, isAdminFlag: await isAdmin() };
});

ipcMain.handle('checker:open-privacy', async () => {
  await shell.openExternal('https://check.piglax.ru');
});

function findWinfr() {
  return new Promise((resolve) => {
    execFile('where.exe', ['winfr.exe'], { windowsHide: true }, (error, stdout) => {
      resolve(error ? null : String(stdout).split(/\r?\n/).map((line) => line.trim()).find(Boolean) || null);
    });
  });
}

async function recoverWithWindowsFileRecovery({ pattern, sourceDrive }) {
  const executable = await findWinfr();
  if (!executable) {
    await dialog.showMessageBox(mainWindow, {
      type: 'warning',
      title: 'Windows File Recovery не найден',
      message: 'Для восстановления очищенной корзины требуется Windows File Recovery.',
      detail: 'Установите Windows File Recovery из Microsoft Store и повторите действие.',
      buttons: ['ОК'],
    });
    return;
  }

  const selected = await dialog.showOpenDialog(mainWindow, {
    title: 'Куда сохранить найденные удалённые данные',
    properties: ['openDirectory', 'createDirectory'],
  });
  if (selected.canceled || !selected.filePaths[0]) return;
  const destination = selected.filePaths[0];
  const source = String(sourceDrive || 'C:').toUpperCase().replace(/[\\/]+$/, '');
  const destinationDrive = path.parse(destination).root.toUpperCase().replace(/[\\/]+$/, '');
  if (source === destinationDrive) {
    await dialog.showMessageBox(mainWindow, {
      type: 'error',
      title: 'Нужен другой диск',
      message: 'Папка назначения находится на том же диске.',
      detail: `Windows File Recovery требует сохранять результат не на ${source}, а на другой диск или USB-накопитель.`,
      buttons: ['ОК'],
    });
    return;
  }

  const safePattern = String(pattern || '*').replace(/["\r\n]/g, '').slice(0, 120) || '*';
  const confirmation = await dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'Запуск восстановления',
    message: 'Windows File Recovery попробует найти удалённые данные.',
    detail: `Источник: ${source}\nМаска: ${safePattern}\nРезультат: ${destination}`,
    buttons: ['Начать', 'Отмена'],
    defaultId: 0,
    cancelId: 1,
  });
  if (confirmation.response !== 0) return;

  const child = spawn(executable, [source, destination, '/regular', '/n', safePattern], {
    windowsHide: false,
  });
  child.on('close', async (code) => {
    const result = await dialog.showMessageBox(mainWindow, {
      type: code === 0 ? 'info' : 'warning',
      title: code === 0 ? 'Восстановление завершено' : 'Восстановление завершено с ошибкой',
      message: code === 0 ? 'Проверьте папку назначения.' : `Windows File Recovery завершился с кодом ${code}.`,
      detail: `Результат сохранён в:\n${destination}`,
      buttons: ['Открыть папку', 'Закрыть'],
      defaultId: 0,
    });
    if (result.response === 0) shell.openPath(destination);
  });
}

ipcMain.handle('checker:sync-remote', async () => {
  try {
    const result = await syncRemoteSignatures();
    return { ok: true, updated: result.updated, version: result.version, count: result.signatures.length };
  } catch (error) {
    return { ok: false, updated: false, error: error.message };
  }
});

ipcMain.on('checker:show-context-menu', (event, payload = {}) => {
  const { path: targetPath, copyText, label, restorePath, recoveryPattern, sourceDrive } = payload;
  const template = [];

  if (targetPath) {
    template.push({
      label: 'Показать в проводнике',
      click: () => shell.showItemInFolder(targetPath),
    });
    template.push({
      label: 'Скопировать путь',
      click: () => clipboard.writeText(targetPath),
    });
  }
  if (copyText && copyText !== targetPath) {
    template.push({
      label: label ? `Скопировать "${label}"` : 'Скопировать',
      click: () => clipboard.writeText(copyText),
    });
  }

  if (targetPath && restorePath) {
    template.push({
      label: 'Восстановить файл из корзины',
      click: async () => {
        const recycleRoot = path.join(path.parse(process.env.SystemRoot || 'C:\\Windows').root, '$Recycle.Bin');
        const resolvedData = path.resolve(targetPath);
        if (!resolvedData.startsWith(path.resolve(recycleRoot) + path.sep)) return;
        let destination = path.resolve(restorePath);
        try {
          const confirmation = await dialog.showMessageBox(mainWindow, {
            type: 'question',
            title: 'Восстановление файла',
            message: 'Восстановить найденный файл из корзины?',
            detail: `Исходный путь:\n${restorePath}\n\nЕсли такой файл уже существует, будет создан файл с суффиксом .restored.`,
            buttons: ['Восстановить', 'Отмена'],
            defaultId: 0,
            cancelId: 1,
          });
          if (confirmation.response !== 0) return;
          await fs.promises.mkdir(path.dirname(destination), { recursive: true });
          try { await fs.promises.access(destination); destination += '.restored'; } catch {  }
          await fs.promises.rename(resolvedData, destination);
          const metaPath = path.join(path.dirname(resolvedData), `$I${path.basename(resolvedData).slice(2)}`);
          await fs.promises.unlink(metaPath).catch(() => {});
          mainWindow?.webContents.send('checker:scan-log', { text: `Восстановлено: ${destination}`, level: 'ok' });
          await dialog.showMessageBox(mainWindow, {
            type: 'info',
            title: 'Файл восстановлен',
            message: 'Восстановление завершено.',
            detail: `Файл восстановлен в:\n${destination}`,
            buttons: ['ОК'],
          });
          shell.showItemInFolder(destination);
        } catch (err) {
          await dialog.showMessageBox(mainWindow, {
            type: 'error',
            title: 'Восстановление не выполнено',
            message: 'Не удалось восстановить файл.',
            detail: err.message,
            buttons: ['ОК'],
          });
          mainWindow?.webContents.send('checker:scan-log', { text: `Не удалось восстановить файл: ${err.message}`, level: 'warn' });
        }
      },
    });
  }

  if (recoveryPattern) {
    template.push({
      label: 'Попробовать восстановить после очистки корзины',
      click: () => { void recoverWithWindowsFileRecovery({ pattern: recoveryPattern, sourceDrive }); },
    });
  }

  template.push({ type: 'separator' });
  template.push({ label: 'Открыть политику конфиденциальности', click: () => shell.openExternal('https://check.piglax.ru') });

  if (template.length === 0) return;
  Menu.buildFromTemplate(template).popup({ window: mainWindow });
});

ipcMain.handle('checker:start-scan', async (event) => {
  const send = (channel, payload) => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    mainWindow.webContents.send(channel, payload);
  };

  const isAdminFlag = await isAdmin();
  let remote;
  try {
    remote = await syncRemoteSignatures();
  } catch (error) {
    send('checker:scan-log', { text: `Не удалось получить сигнатуры с сервера: ${error.message}`, level: 'alert' });
    throw new Error('Для проверки требуется подключение к серверу сигнатур.');
  }
  send('checker:scan-log', {
    text: `Получены сигнатуры: ${remote.signatures.length}`,
    level: 'ok',
  });
  const scannerRuns = [];

  for (const scanner of scanners) {
    send('checker:scan-log', { text: `Сканирую: ${scanner.label}...` });
    let result;
    try {
      result = await scanner.run({ isAdminFlag });
    } catch (err) {
      result = { findings: [], skipped: true, skipReason: `Внутренняя ошибка сканера: ${err.message}` };
    }
    const run = { id: scanner.id, label: scanner.label, ...result };
    scannerRuns.push(run);

    if (run.skipped) {
      send('checker:scan-log', { text: `  пропущено: ${run.skipReason}`, level: 'warn' });
    } else {
      send('checker:scan-log', { text: `  готово, найдено совпадений: ${run.findings.length}`, level: run.findings.length ? 'alert' : 'ok' });
    }
  }

  const report = buildReport(scannerRuns);
  const scannersSummary = scannerRuns.map((r) => ({
    id: r.id,
    label: r.label,
    skipped: !!r.skipped,
    skipReason: r.skipReason || null,
    findingsCount: r.findings ? r.findings.length : 0,
  }));

  return { report, scannersSummary, isAdminFlag };
});
