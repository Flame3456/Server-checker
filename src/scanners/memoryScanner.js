'use strict';

const { execFile } = require('child_process');
const { getSignatures } = require('../signatures');

const POWERSHELL_READER = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class AxolandMemoryReader {
  [StructLayout(LayoutKind.Sequential)]
  public struct Mbi {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public UIntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
  }

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out Mbi info, UIntPtr length);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr read);

  public sealed class Hit {
    public string Marker { get; set; }
    public long Address { get; set; }
  }

  public sealed class ScanResult {
    public List<Hit> Hits { get; set; }
    public int ErrorCode { get; set; }
    public int Regions { get; set; }
    public long BytesRead { get; set; }
    public int PartialReads { get; set; }
    public int ReadFailures { get; set; }
    public int LastError { get; set; }
    public ScanResult() {
      Hits = new List<Hit>();
    }
  }

  [StructLayout(LayoutKind.Sequential)]
  struct Luid { public uint LowPart; public int HighPart; }
  [StructLayout(LayoutKind.Sequential)]
  struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool LookupPrivilegeValue(string systemName, string name, out Luid luid);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges newState, uint length, IntPtr previous, IntPtr returnLength);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr GetCurrentProcess();

  static void EnableDebugPrivilege() {
    IntPtr token;
    if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x0008, out token)) return;
    try {
      Luid luid;
      if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) return;
      var privileges = new TokenPrivileges { Count = 1, Luid = luid, Attributes = 0x2 };
      AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
    } finally { CloseHandle(token); }
  }

  public static ScanResult Scan(int pid, string[] markers, int maxBytes) {
    var result = new ScanResult();
    EnableDebugPrivilege();
    var process = OpenProcess(0x1410, false, pid);
    if (process == IntPtr.Zero) {
      result.ErrorCode = Marshal.GetLastWin32Error();
      return result;
    }
    try {
      IntPtr address = IntPtr.Zero;
      int scanned = 0;
      while (scanned < maxBytes) {
        Mbi info;
        if (VirtualQueryEx(process, address, out info, (UIntPtr)Marshal.SizeOf(typeof(Mbi))) == UIntPtr.Zero) break;
        ulong regionSize = info.RegionSize.ToUInt64();
        if (regionSize == 0) break;
        result.Regions++;
        uint protect = info.Protect & 0xff;
        bool readable = info.State == 0x1000 && (info.Protect & 0x100) == 0 &&
          (protect == 0x02 || protect == 0x04 || protect == 0x08 || protect == 0x20 || protect == 0x40 || protect == 0x80);
        if (readable) {
          ulong offset = 0;
          while (offset < regionSize && scanned < maxBytes) {
            int length = (int)Math.Min(1024 * 1024, Math.Min(regionSize - offset, (ulong)(maxBytes - scanned)));
            var buffer = new byte[length];
            UIntPtr read;
            var current = new IntPtr(unchecked(info.BaseAddress.ToInt64() + (long)offset));
            bool complete = ReadProcessMemory(process, current, buffer, (UIntPtr)length, out read);
            int actual = (int)Math.Min((ulong)length, read.ToUInt64());
            if (actual > 0) {
              var ascii = Encoding.ASCII.GetString(buffer, 0, actual);
              var unicode = Encoding.Unicode.GetString(buffer, 0, actual - (actual % 2));
              foreach (var marker in markers) {
                if (ascii.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    unicode.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0) {
                  result.Hits.Add(new Hit { Marker = marker, Address = current.ToInt64() });
                }
              }
              result.BytesRead += actual;
              if (!complete) result.PartialReads++;
            } else if (!complete) {
              result.ReadFailures++;
              result.LastError = Marshal.GetLastWin32Error();
            }
            scanned += Math.Max(actual, length);
            offset += (ulong)length;
          }
        }
        address = new IntPtr(unchecked(info.BaseAddress.ToInt64() + (long)regionSize));
      }
    } finally {
      CloseHandle(process);
    }
    return result;
  }
}
'@
$markers = ConvertFrom-Json '__MARKERS__'
$targets = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object {
    $_.Name -match '^(java|javaw|Minecraft|Minecraft.Windows)(\.exe)?$' -or
    $_.CommandLine -match '(?i)minecraft|net\.minecraft|fabric-loader|forge'
  } |
  Select-Object ProcessId, Name
$hits = @()
$diagnostics = @()
if (-not $targets) {
  $diagnostics += [PSCustomObject]@{ Code = 'NO_TARGET_PROCESS'; Message = 'Процессы Java/Minecraft не найдены' }
}
foreach ($target in $targets) {
  try {
    $scan = [AxolandMemoryReader]::Scan([int]$target.ProcessId, [string[]]$markers, 1073741824)
    if ($scan.ErrorCode -ne 0) {
      $diagnostics += [PSCustomObject]@{ Code = 'OPEN_PROCESS_FAILED'; Pid = [int]$target.ProcessId; ProcName = [string]$target.Name; Win32Error = $scan.ErrorCode }
    } elseif ($scan.BytesRead -eq 0 -and $scan.ReadFailures -gt 0) {
      $diagnostics += [PSCustomObject]@{ Code = 'READ_PROCESS_FAILED'; Pid = [int]$target.ProcessId; ProcName = [string]$target.Name; Win32Error = $scan.LastError; ReadFailures = $scan.ReadFailures }
    } else {
      $diagnostics += [PSCustomObject]@{ Code = 'SCANNED'; Pid = [int]$target.ProcessId; ProcName = [string]$target.Name; Regions = $scan.Regions; BytesRead = $scan.BytesRead; PartialReads = $scan.PartialReads; ReadFailures = $scan.ReadFailures }
    }
    foreach ($hit in $scan.Hits) {
      $hits += [PSCustomObject]@{
        Marker = $hit.Marker
        Address = ('0x{0:X}' -f $hit.Address)
        Pid = [int]$target.ProcessId
        ProcName = [string]$target.Name
      }
    }
  } catch {
    $diagnostics += [PSCustomObject]@{ Code = 'SCAN_EXCEPTION'; Pid = [int]$target.ProcessId; ProcName = [string]$target.Name; Message = $_.Exception.Message }
  }
}
@{ hits = @($hits); diagnostics = @($diagnostics) } | ConvertTo-Json -Compress -Depth 5
`;

function encodedPowerShell(script) {
  return Buffer.from(script, 'utf16le').toString('base64');
}

function runEncodedPowerShell(script) {
  return new Promise((resolve) => {
    const systemRoot = process.env.SystemRoot || 'C:\\Windows';
    const powershellPath = process.arch === 'ia32' && process.env.PROCESSOR_ARCHITEW6432
      ? `${systemRoot}\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe`
      : `${systemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
    execFile(powershellPath, [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-EncodedCommand', encodedPowerShell(script),
    ], { timeout: 90000, maxBuffer: 16 * 1024 * 1024, windowsHide: true }, (error, stdout, stderr) => {
      resolve({ ok: !error, output: stdout || '', error: error ? error.message : '', stderr: stderr || '' });
    });
  });
}

module.exports = {
  id: 'memory_strings',
  label: 'Память Minecraft/Java (read-only поиск строк)',

  async run() {
    if (process.platform !== 'win32') {
      return { findings: [], skipped: true, skipReason: 'Сканирование памяти доступно только в Windows' };
    }

    const signatures = getSignatures()
      .filter((sig) => ['ghost', 'loader', 'client'].includes(sig.category) && sig.name.length >= 5);
    const markers = [...new Set(signatures
      .map((sig) => sig.name)
      .concat(['doomsday', 'systemdlc']))];
    const signatureMeta = new Map(signatures.map((sig) => [sig.name.toLowerCase(), sig]));
    const script = POWERSHELL_READER.replace('__MARKERS__', JSON.stringify(markers));
    const execution = await runEncodedPowerShell(script);
    if (!execution.ok) {
      return { findings: [], skipped: true, skipReason: `Память не прочитана: ${execution.error || execution.stderr || 'PowerShell завершился с ошибкой'}` };
    }

    let payload;
    try { payload = JSON.parse(execution.output.trim()); } catch { payload = null; }
    if (!payload || typeof payload !== 'object') {
      return { findings: [], skipped: true, skipReason: 'Память не прочитана: PowerShell вернул некорректный ответ' };
    }
    const diagnostics = Array.isArray(payload.diagnostics) ? payload.diagnostics : [];
    const hits = Array.isArray(payload.hits) ? payload.hits : [];
    if (!hits.length && diagnostics.some((item) => item?.Code === 'NO_TARGET_PROCESS')) {
      return { findings: [], skipped: true, skipReason: 'Процессы Java/Minecraft не запущены — поиск памяти пропущен', meta: { diagnostics } };
    }
    if (!hits.length && diagnostics.some((item) => item?.Code === 'OPEN_PROCESS_FAILED')) {
      const errors = diagnostics
        .filter((item) => item?.Code === 'OPEN_PROCESS_FAILED')
        .map((item) => `${item.ProcName || 'process'}: Win32 ${item.Win32Error}`)
        .join(', ');
      return { findings: [], skipped: true, skipReason: `Нет доступа к памяти процесса (${errors}). Запустите Checker с теми же или более высокими правами, что и Minecraft.`, meta: { diagnostics } };
    }
    if (!hits.length && diagnostics.some((item) => item?.Code === 'READ_PROCESS_FAILED')) {
      const errors = diagnostics
        .filter((item) => item?.Code === 'READ_PROCESS_FAILED')
        .map((item) => `${item.ProcName || 'process'}: Win32 ${item.Win32Error}`)
        .join(', ');
      return { findings: [], skipped: true, skipReason: `Процесс открыт, но Windows не разрешила чтение страниц (${errors}). Проверьте разрядность сборки и запустите Minecraft и Checker с одинаковыми правами.`, meta: { diagnostics } };
    }
    const findings = [];
    const seen = new Set();
    for (const hit of hits) {
      const key = `${hit.Pid}:${String(hit.Marker).toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        signature: String(hit.Marker).toLowerCase(),
        category: 'memory',
        distinctive: signatureMeta.get(String(hit.Marker).toLowerCase())?.distinctive ?? true,
        evidenceType: 'memory_string',
        detail: `В памяти процесса ${hit.ProcName} (PID ${hit.Pid}) найдена строка "${hit.Marker}" по адресу ${hit.Address}. Это сильная зацепка, но не самостоятельное доказательство инжекта.`,
        path: null,
        scanner: this.id,
      });
    }
    return { findings, skipped: false, meta: { processesScanned: 'java/javaw/Minecraft', markersChecked: markers.length, diagnostics } };
  },
};
