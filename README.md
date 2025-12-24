# Scynesthesia Optimizer

![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11-0078D6?logo=windows&logoColor=white)
![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)
![Language](https://img.shields.io/badge/UI-English-3CB371)
![Status](https://img.shields.io/badge/Focus-Performance%20%7C%20Stability%20%7C%20Privacy-8A2BE2)

A professional-grade, modular PowerShell 5.1 suite for Windows 10/11 that tunes performance, trims latency for gaming, and debloats safely. Scynesthesia pairs **hardware-aware logic** with **guided menus** so you can optimize confidently without breaking your OS.

---

## Overview
Scynesthesia Optimizer is built for power users, creators, and competitive gamers who want **lower latency, leaner services, and consistent stability** without sacrificing restore options. The toolkit is organized into specialized modules (.psm1) that can run independently or through the guided launcher. Every change is gated by safety rails such as restore points, hardware detection, and reversible tweaks.

### Philosophy: Performance Without Regret
- **Safety first**: creates restore points, uses non-destructive debloat lists, and favors reversible settings.
- **Hardware-aware**: adapts to laptops/desktops, storage type, and device capabilities for MSI mode and power tuning.
- **Modular by design**: focused modules let you run only what you need and extend the toolkit without editing the core.
- **Focused UX**: all menus and prompts are provided in US English for clarity.

---

## Core Modules
| Area | What it covers | Example actions |
| --- | --- | --- |
| **Performance** | Kernel timers, MPO, HAGS, power throttling | Adjusts scheduler balance, toggles Hardware Accelerated GPU Scheduling, tunes power limits for foreground tasks |
| **Network & Hardcore** | TCP tuning, MTU discovery, bufferbloat mitigation | Enables RSS/CTCP, discovers optimal MTU, sets `TCPNoDelay`/`TcpAckFrequency`, applies hardcore NIC power overrides |
| **Gaming** | Input latency, scheduler priorities, FSO overrides | Tunes HID/USB polling latency, boosts game process priority, disables Fullscreen Optimizations for targeted titles |
| **Services & Debloat** | Service silencing, telemetry opt-out, OEM cleanup | Disables noisy telemetry services, trims OEM bloat via curated lists, manages SysMain/hibernation by device type |
| **Software & Updates** | Winget integration, update posture | Installs/removes software through winget, switches Windows Update to **Notify Only** to avoid surprise reboots |
| **UI Tweaks** | Explorer and shell ergonomics | Restores classic context menu, adds **Take Ownership**, applies "Explorer Pro" options for faster navigation |

---

## Key Features
- **Modular architecture**: self-contained `.psm1` modules (performance, network, gaming, debloat, UI, repair) that can be run individually or through the main menu.
- **Streamlined experience**: US English prompts, summaries, and confirmations throughout the CLI.
- **Safety-first workflow**: restore point creation, optional backups, and hardware-aware branching to avoid risky tweaks on laptops or legacy drivers.
- **"Unbreakable" logic**: prefers reversible registry edits, non-destructive app lists, and explicit user confirmations for hardcore or experimental lanes.
- **Latency-aware defaults**: profiles optimized for consistent frametimes, predictable input response, and low network jitter.

---

## Installation & Usage
> Run from an **elevated PowerShell 5.1** session on Windows 10/11. The script will request admin if not already elevated.

### One-liner (recommended)
```powershell
start powershell -ArgumentList '-NoExit -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; irm https://raw.githubusercontent.com/scynesthesia/scynesthesia-optimizer/main/setup.ps1 | iex"'
```

### Local clone
```powershell
# Clone
 git clone https://github.com/scynesthesia/scynesthesia-optimizer.git
 cd scynesthesia-optimizer

# Launch the menu
 Set-ExecutionPolicy Bypass -Scope Process
 ./scynesthesiaoptimizer.ps1
```

### Requirements
- PowerShell **5.1**
- Windows **10/11**
- Administrator privileges (for system-level tweaks, restore points, and winget installations)

---

## Guided Experience
1. Select a **profile**: Safe, Aggressive, Gaming, Network/Hardcore, or Repair.
2. Confirm optional modules (e.g., hardcore network lane, MSI mode, debloat depth).
3. Review summary prompts before applying changes.

---

## Profiles at a Glance
| Profile | Purpose | Notable actions |
| --- | --- | --- |
| **Safe** | Conservative defaults for daily use | Restore point, privacy hardening, safe debloat, hardware-aware SysMain/hibernation, keeps visuals intact |
| **Aggressive** | Lean background footprint | Everything in Safe plus deeper debloat, faster service shutdown, disables background apps/visual effects |
| **Gaming** | Low-latency add-on | Scheduler priority bias for games, Scynesthesia Gaming Mode power plan, HID/USB latency tweaks, MSI mode where supported |
| **Network** | Latency-focused networking | RSS/CTCP, DNS hardening, Nagle off, MTU validation, bufferbloat mitigation |
| **Hardcore Network** | Experimental edge | Dynamic MTU discovery via fragmentation tests, PnPCapabilities overrides, advanced TCP parameters |

> Profiles are additive: apply **Safe** or **Aggressive**, then layer **Gaming** and **Network/Hardcore** modules as needed.

---

## Safety Nets & Revert Paths
- **Restore points**: created before impactful changes for quick rollback.
- **Config-driven debloat**: app lists live in `config/apps.json`; edit or trim entries before running.
- **Power plans reset**: `powercfg /restoredefaultschemes` restores stock plans if you want to undo gaming modes.
- **Service toggles**: many services are disabled, not removed, making them easy to re-enable.

---

## Quick Module Map
- `setup.ps1`: remote installer and bootstrapper.
- `scynesthesiaoptimizer.ps1`: entry point and menu router.
- `modules/`: specialized `.psm1` modules (performance, network, gaming, debloat, privacy, UI, repair, aggressive profiles).
- `config/`: editable configs such as `apps.json` for debloat scope.

---

## Contributing
Contributions are welcome in **English**. Please:
1. Fork and work on a feature branch.
2. Keep new tweaks modular within `modules/` and respect the safety/restore workflow.
3. Document new flags or app list changes in comments or the README.
4. Test on Windows (PowerShell 5.1) and include notes on the profiles/modules exercised.

---

## License
Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## Support
- Open an issue for bugs or feature requests; include PowerShell version, Windows build, and which modules you ran.
- PR discussions are welcome in English.
