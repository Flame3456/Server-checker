'use strict';

const BASE_WEIGHT = {
  minecraft_log: 45,
  minecraft_mod: 42,
  minecraft_version: 40,
  minecraft_version_file: 38,
  minecraft_config_ext: 25,
  minecraft_root_folder: 22,
  minecraft_config_folder: 20,
  minecraft_options: 12,

  process: 30,
  installed_program: 28,
  startup_registry: 26,
  startup_folder: 24,
  usn_journal: 28,
  prefetch: 18,

  recent_file: 12,
  jumplist: 12,
  browser_history: 5,
  filesystem_file: 22,
  filesystem_folder: 20,

  injected_module: 48, 
  driver: 40,          
  service: 28,
  memory_string: 24,

  deleted_artifact: 32,
  axoland_usage: 50,
};

const MINECRAFT_EVIDENCE_PREFIX = 'minecraft_';

function weightFor(finding) {
  const base = BASE_WEIGHT[finding.evidenceType] ?? 10;
  const isMinecraftContext = finding.evidenceType.startsWith(MINECRAFT_EVIDENCE_PREFIX);

const distinctiveMultiplier = finding.distinctive
    ? 1
    : isMinecraftContext ? 0.65 : 0.3;
  return base * distinctiveMultiplier;
}

function explainSignature(signature, evidenceList) {
  const total = evidenceList.reduce((s, e) => s + e.weight, 0);
  const hasStrong = evidenceList.some((e) => e.weight >= 35);
  const hasMedium = evidenceList.some((e) => e.weight >= 18 && e.weight < 35);
  const onlyWeak = evidenceList.every((e) => e.weight < 18);

  let verdict;
  let verdictText;
  if (total >= 70 || (hasStrong && evidenceList.length >= 2)) {
    verdict = 'confirmed';
    verdictText = `~100% — обнаружены прямые следы клиента "${signature}" (файл/процесс/лог), случайное совпадение практически исключено.`;
  } else if (hasStrong) {
    verdict = 'likely';
    verdictText = `Высокая вероятность — найдена как минимум одна серьёзная улика по "${signature}" (файл клиента, установленная программа или запись в игровом логе).`;
  } else if (hasMedium) {
    verdict = 'suspicious';
    verdictText = `Есть основания для ручной проверки по "${signature}" — совпадение найдено, но само по себе не является стопроцентным доказательством.`;
  } else {
    verdict = 'weak';
    verdictText = `Слабый след "${signature}" (например, только упоминание в истории браузера) — это НЕ доказательство использования чита, возможно случайное совпадение или простое любопытство.`;
  }
  return { total, verdict, verdictText, onlyWeak };
}

function buildReport(scannerRuns) {
  const bySignature = new Map();
  const axolandConnectionFound = scannerRuns.some((run) =>
    run.id === 'axoland_connection' && run.meta?.connectionFiles?.length > 0
  );

  for (const run of scannerRuns) {
    if (run.skipped) continue;
    for (const finding of run.findings) {
      if (finding.category === 'server_connection') continue;
      const weight = weightFor(finding);
      const entry = bySignature.get(finding.signature) || {
        signature: finding.signature,
        category: finding.category,
        evidence: [],
      };
      entry.evidence.push({ ...finding, weight });
      bySignature.set(finding.signature, entry);
    }
  }

  const perSignature = [...bySignature.values()].map((entry) => {
    const { total, verdict, verdictText, onlyWeak } = explainSignature(entry.signature, entry.evidence);
    const axolandEvidence = entry.evidence.some((e) => e.evidenceType === 'axoland_usage');
    const axolandVerdict = axolandEvidence
      ? 'possible'
      : axolandConnectionFound ? 'not_confirmed' : 'no_connection';
    const axolandText = axolandEvidence
      ? 'Возможное использование на Axoland: сигнатура клиента и запись подключения найдены в одном игровом логе.'
      : axolandConnectionFound
        ? 'Подключение к Axoland найдено, но связь именно с этим клиентом по логам не подтверждена.'
        : 'Подключение к Axoland в доступных логах не найдено.';

    return {
      signature: entry.signature,
      category: entry.category,
      score: Math.round(total),
      verdict,
      verdictText,
      onlyWeak,
      axolandVerdict,
      axolandText,
      evidence: entry.evidence
        .slice()
        .sort((a, b) => b.weight - a.weight)
        .map((e) => ({ evidenceType: e.evidenceType, detail: e.detail, path: e.path, restorePath: e.restorePath, recoveryStatus: e.recoveryStatus, recoveryPattern: e.recoveryPattern, sourceDrive: e.sourceDrive, weight: Math.round(e.weight) })),
    };
  });

  perSignature.sort((a, b) => b.score - a.score);

  const confirmedCount = perSignature.filter((s) => s.verdict === 'confirmed').length;
  const likelyCount = perSignature.filter((s) => s.verdict === 'likely').length;
  const suspiciousCount = perSignature.filter((s) => s.verdict === 'suspicious').length;

  const topScore = perSignature.length ? perSignature[0].score : 0;
  const overallScore = Math.min(100, topScore);

  let overallVerdict;
  let overallText;
  if (confirmedCount > 0) {
    overallVerdict = 'confirmed';
    overallText = `Обнаружены прямые следы чит-клиента(ов): ${perSignature
      .filter((s) => s.verdict === 'confirmed')
      .map((s) => s.signature)
      .join(', ')}. Это не совпадение — рекомендуется бан/дисквалификация.`;
  } else if (likelyCount > 0) {
    overallVerdict = 'likely';
    overallText = `Найдены серьёзные, но не стопроцентные улики по: ${perSignature
      .filter((s) => s.verdict === 'likely')
      .map((s) => s.signature)
      .join(', ')}. Рекомендуется ручная проверка / повторный скан с правами администратора.`;
  } else if (suspiciousCount > 0) {
    overallVerdict = 'suspicious';
    overallText = 'Найдены слабые/косвенные совпадения. Однозначных доказательств использования читов нет — нужна доп. проверка вручную.';
  } else if (perSignature.length > 0) {
    overallVerdict = 'weak';
    overallText = 'Найдены только очень слабые совпадения (например, в истории браузера) — скорее всего, это не читер.';
  } else {
    overallVerdict = 'clean';
    overallText = 'Совпадений с базой известных чит-клиентов и лоадеров не найдено.';
  }

  return { overallScore, overallVerdict, overallText, perSignature, axolandConnectionFound };
}

module.exports = { buildReport, weightFor };
