# Scynesthesia Optimizer

![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11-0078D6?logo=windows&logoColor=white)
![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)
![Language](https://img.shields.io/badge/UI-English-3CB371)
![Status](https://img.shields.io/badge/Focus-Performance%20%7C%20Stability%20%7C%20Privacy-8A2BE2)

An authoritative, security-first, performance-obsessed PowerShell 5.1 suite for Windows 10/11. Scynesthesia Optimizer is a **modular Windows hardening and latency-tuning environment**, not a disposable batch script. It prioritizes reversibility, telemetry awareness, and predictable frametimes for gaming, streaming, and low-jitter networking.

> [!NOTE]
> All prompts and outputs are in English. Run from an **elevated PowerShell 5.1** session; elevation is requested if missing.

---

## Run once (quick start)
Execute directly—no manual cloning required.

```powershell
start powershell -ArgumentList '-NoExit -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; irm https://raw.githubusercontent.com/scynesthesia/scynesthesia-optimizer/main/setup.ps1 | iex"'
```

> [!WARNING]
> Network and registry changes require admin rights. A restore point is created before impactful actions when supported.

### Local workflow
```powershell
git clone https://github.com/scynesthesia/scynesthesia-optimizer.git
cd scynesthesia-optimizer
Set-ExecutionPolicy Bypass -Scope Process
./scynesthesiaoptimizer.ps1
```

---

## Architecture
- **Modular PowerShell suite**: Windows 10/11 modules live in `modules/` and are dynamically loaded via `modules.map.psd1` to keep dependencies explicit and discoverable.
- **Central `$Context`**: tracks persistence, hardware detection, prior state, and rollback metadata so modules can safely undo or summarize actions.
- **Guided entry points**: `setup.ps1` bootstraps securely; `scynesthesiaoptimizer.ps1` routes to profiles and modules without editing core files.
- **Non-destructive defaults**: registry writes go through guarded helpers, and hardware-aware branches avoid unsafe tweaks on unsupported systems.

---

## Pillars

### Network Hardcore
- BBR support and TCP hygiene tuned for modern stacks.
- Binary-search MTU discovery with safe fallbacks and rollback context captured.
- Bufferbloat mitigation plus RSS base CPU pinning.
- Optional IPv6 disablement logged to `$Context` for reliable reversal.

### Gaming & Low Latency
- Interactive QoS manager with DSCP 46 defaults for latency-critical traffic.
- qWave autostart and network service alignment for games.
- CPU/GPU priority helpers, HID/latency tweaks, and MSI awareness.
- Game overlay silencing (GameDVR off) to keep render latency predictable.

### Hardware Intelligence
- Detects laptops and thin-and-light devices to keep defaults non-destructive.
- Modern Standby awareness and battery safeguards before applying power or NIC overrides.
- Applies aggressive modes only when thermals and power profiles allow safe operation.

### Safety & Recovery
- Restore points prior to high-impact changes when available.
- `Set-RegistryValueSafe` for registry writes and sanity checks.
- Network rollback actions captured in `$Context` alongside summaries for traceability.
- Session summaries enumerate what changed and how to undo it.

---

## Design philosophy: why safety-first matters for power users
- **Predictable reversibility** beats raw aggressiveness; every hardcore toggle is paired with a documented rollback path.
- **Hardware-awareness** prevents laptop battery damage and thermal runaway on thin devices.
- **Performance with auditability**: session summaries and guarded helpers make tweaks explainable and repeatable.

| Gaming lane | Hardcore network lane |
| --- | --- |
| Prioritizes DSCP 46, HID latency, and foreground scheduler boosts | Pushes MTU/BBR/queue depth to the edge with rollback breadcrumbs |
| Keeps visual fidelity unless explicitly disabled | Trades cosmetics for determinism; favors packet discipline over comfort |
| Ideal for competitive play and streaming | Ideal for lab-grade jitter chasing with documented exit ramps |

---

## Safety & recovery practices
- Restore points and reversible registry edits come first; destructive actions are avoided by default.
- Non-destructive debloat lists and service toggles favor disablement over removal.
- Network tweaks (MTU, IPv6, NIC power states) are tracked for explicit rollback instructions.

> [!TIP]
> If something feels off, rerun the optimizer, review the session summary, and select the rollback options captured in `$Context`.

---

## Community extensibility
1. Add a new module under `modules/` and export functions you want the launcher to surface.
2. Register the module in `modules.map.psd1` so it can be discovered and loaded dynamically.
3. Follow existing coding style: guarded registry writes, `$Context` updates for persistence/rollback, and English-only prompts.
4. Keep changes modular—avoid editing core scripts unless you are extending routing or context behavior.
5. Test on Windows 10/11 with PowerShell 5.1 and note which profiles/modules you exercised.

---

## Support & issue reporting
- Open an issue with your Windows build, PowerShell version, selected profile/module, and whether hardcore networking was enabled.
- Contributions are welcome in English and should document any new flags or safety considerations.

## Troubleshooting
### Antivirus or endpoint protection false positives
Because this project modifies system settings and can disable/enable network adapters, some antivirus or EDR tools may flag it as suspicious (false positive). If the optimizer fails to launch, exits unexpectedly, or specific actions are blocked:
- Temporarily allowlist the folder where you extracted the optimizer (including `scynesthesiaoptimizer.ps1` and `modules/`).
- Ensure PowerShell is running as Administrator and that script execution is permitted for the current process.
- Re-run the optimizer after confirming the allowlist, then review the session log for any security-tool blocks.

If you believe your security tool is blocking a legitimate action, capture the log file from `%TEMP%\ScynesthesiaOptimizer` and include it with your issue report.

## Safety improvements (recommended)
For the most resilient experience, consider the following enhancements:
1. **Immediate rollback flush after high-impact changes**: persist rollback state right after critical or high-impact operations to reduce crash windows.
2. **Hardened rollback metadata**: keep failed rollback entries so retries are possible if permissions or registry state change later.
3. **Network recovery fallback**: if MTU rollback or adapter re-enable fails, offer a guided recovery step (e.g., staged netsh reset and reboot guidance).
4. **Integrity verification for remote installs**: add hash/signature validation in the installer workflow to reduce supply-chain risk.

## License
Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
