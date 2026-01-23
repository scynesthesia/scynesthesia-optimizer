# Scynesthesia Optimizer v1.0

![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11-0078D6?logo=windows&logoColor=white)
![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)
![Language](https://img.shields.io/badge/UI-English-3CB371)
![Status](https://img.shields.io/badge/Engine-Transactional%20Performance-8A2BE2)
![Mode](https://img.shields.io/badge/Audit-Option%207-2F855A)

A transactional optimization engine for Windows 10/11. Scynesthesia Optimizer v1.0 is a rollback-first platform for low-level registry, kernel, and network overrides with explicit audit trails. It targets deterministic frametime behavior and predictable latency in gaming, streaming, and network-heavy workloads.

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

## Why Scynesthesia Optimizer is different
Scynesthesia Optimizer is built like a transactional system, not a tweak pack. Every module is reversible, auditable, and context-aware. The engine records state before touching critical subsystems, executes guarded changes, and summarizes rollback actions for deterministic recovery.

**What makes it distinct:**
- **Rollback engine by design**: every high-impact action is paired with a traceable revert path.
- **Modular core**: discrete, testable modules loaded from `modules/` and routed via `modules.map.psd1`.
- **Context intelligence**: a shared `$Context` object persists device/hardware detection, prior state, and rollback metadata.
- **Predictable frametimes**: tuning favors low jitter and stable render latency, not blind benchmarking gains.

## Engineering Transparency
For a deep-dive into the technical justification and risk analysis of our kernel and network tweaks, see our Technical Reference.
You can find it in [docs/technical-reference.md](docs/technical-reference.md).

---

## Core modules: the performance stack

### Kernel Security
- Strategic mitigations management for controlled latency tradeoffs.
- BCD timer alignment for consistent scheduling.
- Guarded registry operations and rollback metadata for safe reversibility.

### Modern Display Stack
- FSO/MPO/WGO optimization pipeline aligned to modern render paths.
- Reduction of overlay and composition overhead for stable frametimes.
- Compatibility-aware switches to avoid legacy conflicts.

### Hardware Hardening
- Native cleanup for legacy PnP devices (HPET, WAN Miniports) with traceable actions.
- Power and thermal awareness to protect thin-and-light devices.
- Safe device toggle logic with recovery guidance.

### Network Hardcore
- WeakHost Model activation and packet consistency tuning.
- MTU discovery with binary search and safe fallback snapshots.
- RSS base CPU pinning, bufferbloat mitigation, and hardened adapter hygiene.

---

## Transactional architecture
- **Modular PowerShell suite**: Windows 10/11 modules live in `modules/` and are dynamically loaded via `modules.map.psd1` to keep dependencies explicit and discoverable.
- **Central `$Context`**: tracks persistence, hardware detection, prior state, and rollback metadata so modules can safely undo or summarize actions.
- **Guided entry points**: `setup.ps1` bootstraps securely; `scynesthesiaoptimizer.ps1` routes to profiles and modules without editing core files.
- **Non-destructive defaults**: registry writes go through guarded helpers, and hardware-aware branches avoid unsafe tweaks on unsupported systems.

---

## Presets overview

| Preset | Target use | Aggressiveness | Rollback coverage | Recommended for |
| --- | --- | --- | --- | --- |
| **Safe** | Daily driver stability | Low | Full | Workstations, creators, business machines |
| **Balanced** | Performance + safety | Medium | Full | Gaming, streaming, productivity |
| **Aggressive** | Max performance | High | Full (with risk flags) | Competitive gaming rigs |
| **Gaming** | Latency + visuals tradeoffs | High | Full (with risk flags) | Competitive play + streaming |

> [!NOTE]
> All presets are reversible through the session summary and rollback actions stored in `$Context`.

---

## Audit Mode (Option 7)
**Option 7** is the verification engine. It inspects the system and validates that optimizations persist, detects OS reversion, and highlights drift—ensuring that your performance posture remains intact between sessions.

**Use Audit Mode when:**
- You suspect Windows updates reverted settings.
- You want proof of applied changes before tournaments or streaming events.
- You need a clean compliance report for baseline enforcement.

---

## Risk disclosure (Aggressive & Gaming)
These presets intentionally push past default Windows safety margins. They are built for expert users who can evaluate and accept tradeoffs.

> [!WARNING]
> **Spectre/Meltdown exposure**: Aggressive/Gaming settings can disable kernel mitigations. This reduces syscall overhead but removes protections against speculative execution attacks.

> [!WARNING]
> **HDCP/DRM breakage**: NVIDIA tweaks can disable HDCP checks. Protected playback (Netflix, Disney+, Prime Video) or DRM authentication may fail. Roll back if protected content breaks.

> [!WARNING]
> **Kernel-level risk**: Disabling mitigations or modifying kernel scheduling behaviors can reduce system security. Use only on trusted, controlled systems.

---

## Design philosophy: performance with accountability
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
### Run diagnostics to identify blocked commands
If parts of the optimizer are failing or not applying, run the diagnostics script from an elevated PowerShell session to see which commands, modules, or OS features are unavailable:
```powershell
./scripts/runtime_diagnostics.ps1
```
The report will flag missing Windows utilities, unavailable cmdlets, and module file issues so you can focus on what is blocked before re-running a preset.

### Antivirus or endpoint protection false positives
Because this project modifies system settings and can disable/enable network adapters, some antivirus or EDR tools may flag it as suspicious (false positive). If the optimizer fails to launch, exits unexpectedly, or specific actions are blocked:
- Temporarily allowlist the folder where you extracted the optimizer (including `scynesthesiaoptimizer.ps1` and `modules/`).
- Ensure PowerShell is running as Administrator and that script execution is permitted for the current process.
- Re-run the optimizer after confirming the allowlist, then review the session log for any security-tool blocks.

If you believe your security tool is blocking a legitimate action, capture the log file from `%TEMP%\ScynesthesiaOptimizer` and include it with your issue report.

---

## Credits & Inspiration
Scynesthesia Optimizer is an evolution of performance research shared by communities like O&O, melodytheneko, and latency-focused hardware enthusiasts who mapped the real-world cost of kernel and driver behavior.

---

## License
Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
