'use strict';

const openConfirmBtn = document.getElementById('openConfirmBtn');
const confirmOverlay = document.getElementById('confirmOverlay');
const cancelConfirmBtn = document.getElementById('cancelConfirmBtn');
const confirmStartBtn = document.getElementById('confirmStartBtn');
const adminPill = document.getElementById('adminPill');
const logSection = document.getElementById('logSection');
const logConsole = document.getElementById('logConsole');
const scanStatus = document.getElementById('scanStatus');
const scanStatusText = document.getElementById('scanStatusText');
const reportSection = document.getElementById('reportSection');
const verdictBanner = document.getElementById('verdictBanner');
const verdictTitle = document.getElementById('verdictTitle');
const verdictScore = document.getElementById('verdictScore');
const verdictBarFill = document.getElementById('verdictBarFill');
const verdictText = document.getElementById('verdictText');
const scannersSummary = document.getElementById('scannersSummary');
const findingsHeading = document.getElementById('findingsHeading');
const findingsList = document.getElementById('findingsList');
const privacyLink = document.getElementById('privacyLink');

const VERDICT_LABEL = {
  confirmed: 'подтверждено',
  likely: 'высокая вероятность',
  suspicious: 'подозрительно',
  weak: 'слабый след',
};

const OVERALL_TITLE = {
  clean: 'Читы не обнаружены',
  weak: 'Только слабые совпадения',
  suspicious: 'Есть подозрительные совпадения',
  likely: 'Высокая вероятность использования читов',
  confirmed: 'Обнаружены прямые следы чит-клиента',
};

const AXOLAND_VERDICT_LABEL = {
  possible: 'Возможное использование на Axoland',
  not_confirmed: 'Связь с Axoland не подтверждена',
  no_connection: 'Подключение к Axoland не найдено',
};

function appendLog({ text, level }) {
  const line = document.createElement('p');
  line.className = 'log-line' + (level ? ` ${level}` : '');
  line.textContent = text;
  logConsole.appendChild(line);
  logConsole.scrollTop = logConsole.scrollHeight;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function requestContextMenu(e, payload) {
  e.preventDefault();
  e.stopPropagation();
  window.checkerAPI.showContextMenu(payload);
}

function renderScannersSummary(summary) {
  scannersSummary.innerHTML = '';
  for (const s of summary) {
    const chip = document.createElement('span');
    chip.className = 'scanner-chip' + (s.skipped ? ' skipped' : s.findingsCount > 0 ? ' has-findings' : '');
    chip.title = s.skipped ? s.skipReason : `Совпадений: ${s.findingsCount}`;
    chip.textContent = s.skipped ? `${s.label} — пропущено` : `${s.label} — ${s.findingsCount}`;
    scannersSummary.appendChild(chip);
  }
}

function renderFindings(perSignature) {
  findingsList.innerHTML = '';
  if (perSignature.length === 0) {
    findingsHeading.hidden = true;
    return;
  }
  findingsHeading.hidden = false;

  for (const sig of perSignature) {
    const card = document.createElement('div');
    card.className = `finding-card sev-${sig.verdict}`;

    const header = document.createElement('div');
    header.className = 'finding-header';

    const left = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'finding-name';
    name.textContent = sig.signature;
    name.addEventListener('contextmenu', (e) =>
      requestContextMenu(e, { copyText: sig.signature, label: sig.signature })
    );
    const meta = document.createElement('div');
    meta.className = 'finding-meta';
    meta.textContent = `${VERDICT_LABEL[sig.verdict]} · вес ${sig.score}`;
    left.appendChild(name);
    left.appendChild(meta);
    const axoland = document.createElement('div');
    axoland.className = `axoland-status axoland-${sig.axolandVerdict || 'no_connection'}`;
    axoland.textContent = AXOLAND_VERDICT_LABEL[sig.axolandVerdict] || AXOLAND_VERDICT_LABEL.no_connection;
    axoland.title = sig.axolandText || '';
    left.appendChild(axoland);

    const chevron = document.createElement('button');
    chevron.className = 'chevron-btn';
    chevron.setAttribute('aria-label', 'Показать улики');
    chevron.innerHTML = '<span class="chevron-icon"></span>';

    header.appendChild(left);
    header.appendChild(chevron);

    const verdictP = document.createElement('div');
    verdictP.className = 'finding-verdict-text';
    verdictP.textContent = sig.verdictText;

    const evidenceWrap = document.createElement('div');
    evidenceWrap.className = 'evidence-list';
    for (const ev of sig.evidence) {
      const item = document.createElement('div');
      item.className = 'evidence-item';
      item.innerHTML = `<span class="evidence-weight">+${ev.weight}</span> ${escapeHtml(ev.detail)}`;
      if (ev.recoveryStatus === 'available') {
        item.classList.add('recovery-available');
        item.title = 'Файл находится в корзине и доступен для восстановления через контекстное меню';
      } else if (ev.recoveryStatus === 'trace_only') {
        item.classList.add('recovery-trace');
        item.title = 'Найден только след удаления; содержимое файла отсутствует';
      }
      if (ev.path || ev.recoveryStatus === 'trace_only') {
        item.classList.add('has-path');
        item.title = ev.recoveryStatus === 'trace_only'
          ? 'Попробовать восстановление через Windows File Recovery'
          : 'ПКМ: показать в проводнике / скопировать путь';
        item.addEventListener('contextmenu', (e) =>
          requestContextMenu(e, { path: ev.path, copyText: ev.path, label: 'путь', restorePath: ev.restorePath, recoveryPattern: ev.recoveryPattern, sourceDrive: ev.sourceDrive })
        );
      }
      evidenceWrap.appendChild(item);
    }

    const toggle = () => {
      const open = evidenceWrap.classList.toggle('open');
      chevron.classList.toggle('open', open);
    };
    header.addEventListener('click', toggle);

    card.appendChild(header);
    card.appendChild(verdictP);
    card.appendChild(evidenceWrap);
    findingsList.appendChild(card);
  }
}

function renderReport({ report, scannersSummary: summary }) {
  verdictBanner.className = `verdict-banner v-${report.overallVerdict}`;
  verdictTitle.textContent = OVERALL_TITLE[report.overallVerdict];
  verdictScore.textContent = String(report.overallScore);
  verdictBarFill.style.width = `${Math.max(4, report.overallScore)}%`;
  verdictText.textContent = report.overallText;

  renderScannersSummary(summary);
  renderFindings(report.perSignature);

  reportSection.hidden = false;
  reportSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function init() {
  const info = await window.checkerAPI.getPlatformInfo();
  if (info.platform !== 'win32') {
    adminPill.textContent = 'внимание: не Windows';
  } else {
    adminPill.textContent = info.isAdminFlag ? 'запущено от администратора' : 'без прав администратора';
    adminPill.classList.add(info.isAdminFlag ? 'is-admin' : 'not-admin');
  }
}

async function runScan() {
  openConfirmBtn.disabled = true;
  openConfirmBtn.textContent = 'Проверка идёт…';
  logSection.hidden = false;
  logConsole.innerHTML = '';
  reportSection.hidden = true;
  scanStatus.classList.add('scanning');
  scanStatusText.textContent = 'Идёт проверка…';

  const unsubscribe = window.checkerAPI.onScanLog(appendLog);

  try {
    const result = await window.checkerAPI.startScan();
    renderReport(result);
    scanStatusText.textContent = 'Проверка завершена';
  } catch (err) {
    appendLog({ text: `Ошибка проверки: ${err.message}`, level: 'alert' });
    scanStatusText.textContent = 'Проверка прервана ошибкой';
  } finally {
    unsubscribe();
    scanStatus.classList.remove('scanning');
    openConfirmBtn.disabled = false;
    confirmStartBtn.disabled = false;
    openConfirmBtn.textContent = 'Проверить снова';
  }
}

openConfirmBtn.addEventListener('click', () => {
  confirmOverlay.hidden = false;
  confirmOverlay.style.display = '';
});

privacyLink.addEventListener('click', (event) => {
  event.preventDefault();
  window.checkerAPI.openPrivacy();
});

confirmOverlay.addEventListener('click', (event) => {
  if (event.target === confirmOverlay) confirmOverlay.hidden = true;
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !confirmOverlay.hidden) confirmOverlay.hidden = true;
});

cancelConfirmBtn.addEventListener('click', () => {
  confirmOverlay.hidden = true;
  confirmOverlay.style.display = '';
});

confirmStartBtn.addEventListener('click', () => {
  confirmOverlay.hidden = true;
  confirmOverlay.style.display = 'none';
  confirmStartBtn.disabled = true;
  void runScan();
});

init();
