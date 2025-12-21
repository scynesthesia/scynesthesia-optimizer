# Scynesthesia Optimizer

A modular, hardware-aware Windows PowerShell optimizer that debloats safely, hardens privacy, and tunes latency for workstations and gaming rigs.

## Highlights
- One-liner bootstrap from PowerShell (no manual download required)
- Profiles for Safe, Aggressive, and Gaming optimizations
- Hardware detection (SSD/HDD, laptop/desktop) to avoid risky tweaks
- Modular scripts for debloat, privacy, performance, and repair
- Built-in restore point creation and rollback guidance
- English and Spanish interactive menus

## Quick Start
Run in **PowerShell as Administrator**:

```powershell
powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass','-NoExit','-Command','irm https://raw.githubusercontent.com/scynesthesia/scynesthesia-optimizer/main/setup.ps1 | iex'"
```

> The installer downloads the latest release, extracts modules to a temporary folder, and launches the interactive menu.

## Architecture at a Glance
- **setup.ps1** – Remote installer that fetches the packaged release and orchestrates extraction.
- **scynesthesiaoptimizer.ps1** – Entry point and bilingual menu router that exposes five main options (Safe, Aggressive, Gaming, Repair, Network) before dispatching to modules.
- **modules/** – Feature-focused modules: `ui`, `debloat`, `privacy`, `performance`, `network`, `hardware`, `gaming`, `aggressive`, `repair`.
- **config/** – Externalized config such as `apps.json` for uninstall lists.

Each module exposes discrete functions so new tweaks can be added without touching the main script.

## Safety First
- **System Restore checkpoint** is created before any change so you can revert quickly.
- **Hardware-aware branching** keeps laptop hibernation, manages SysMain differently for SSD vs HDD, and guards OEM services.
- **User prompts** confirm impactful steps (e.g., hardcore gaming power tweaks).
- **Logs** are written where supported to aid auditing.

### Backup & Revert
- Use Windows **System Restore** to roll back to the automatically created checkpoint.
- The optimizer keeps a **non-destructive posture**: app removal lists live in `config/apps.json` and can be edited before execution.

## Profiles
| Profile | Purpose | Notable Actions |
| --- | --- | --- |
| **Safe** | Conservative defaults for everyday systems. | Creates restore point, applies privacy hardening, removes common bloat (Safe list), keeps visual effects, hardware-aware SysMain/hibernation. |
| **Aggressive** | Deep clean for minimal background noise. | Everything in Safe, plus expanded debloat, faster service shutdown, disables background apps and visual effects. |
| **Gaming** | Low-latency add-on for players. | Enables gaming scheduler priorities, custom gaming power plan, network Nagle/TCP tweaks, MSI mode where compatible. |

Profiles are additive: run Safe or Aggressive first, then layer the Gaming add-on for latency tuning.

### Network Tiers (Network Tweaks Menu)
| Tier | Focus | Core Actions |
| --- | --- | --- |
| **Safe** | Stable connectivity with sensible defaults. | DNS hardening, TCP autotuning, reliability/stability policies. |
| **Aggressive** | Privacy-centric footprint reduction. | Disables telemetry, Delivery Optimization, and LLMNR for lower background noise. |
| **Gaming** | Latency-first networking. | Enables RSS, disables Nagle's algorithm and Energy Efficient Ethernet. |
| **Hardcore** | Experimental throughput/latency edge. | Dynamic MTU discovery, PnPCapabilities overrides, advanced kernel parameters. |

## Notable Tweaks
### System & Performance
- Adjusts **processor scheduling** (Win32PrioritySeparation) for consistent frametimes.
- Tunes **SysMain** based on storage type; manages **hibernation** depending on laptop/desktop.
- Optimizes **service timeouts** and **menu display delay** for snappier UI.

### Network
- Sets **NetworkThrottlingIndex**, **TcpAckFrequency**, and **TCPNoDelay** for ultra-low latency.
- Resets **WinSock** and related stacks via repair module when requested.
- **Hardcore Network Engine**: optional lane with dynamic MTU discovery via fragmentation tests, bufferbloat mitigation through receive buffer tuning, and NIC power management annihilation (PnPCapabilities overrides).

### Gaming
- Creates a dedicated **Scynesthesia Gaming Mode** power plan and can apply hardcore AC tweaks.
- Prioritizes **GPU/CPU scheduler** settings for foreground games.
- Attempts **MSI mode** for supported GPU/NIC devices to reduce interrupt contention.

## Configuration: `config/apps.json`
- **SafeRemove**: baseline bloatware removal list.
- **AggressiveRemove**: deeper removal set for clean installations.
- To keep an app, delete or comment the entry before running; no hardcoded removals live in the scripts.

## Language Support
Interactive menus and prompts are available in **English** and **Spanish**. The UI module handles locale selection at launch.

## Revert / Rollback Options
1. **System Restore** – revert to the checkpoint created before optimization.
2. **Power plan resets** – use `powercfg /restoredefaultschemes` if you want to discard custom plans.
3. **App reinstalls** – because removals are driven by `apps.json`, rerun with the desired list trimmed or reinstall via Microsoft Store.

## Notices & Prerequisites
- Run from an **elevated PowerShell session**.
- Recommended on **Windows 10/11**. Some tweaks require modern firmware/driver support for MSI mode.
- Corporate-managed devices may block certain registry changes or downloads.
- Always back up critical data before system-wide tweaks.

## Release v1.0
The inaugural tagged release bundles the modular scripts, EN/ES UI, Safe/Aggressive profiles, and the Gaming add-on with restore point creation and hardware-aware safeguards.

## Manual Install
```powershell
# Clone
git clone https://github.com/scynesthesia/scynesthesia-optimizer.git
cd scynesthesia-optimizer

# Run
Set-ExecutionPolicy Unrestricted -Scope Process
./scynesthesiaoptimizer.ps1
```

## Contributing
1. Fork and create a feature branch.
2. Follow PowerShell best practices; keep new tweaks modular within `modules/`.
3. Update `config/apps.json` thoughtfully and document changes in comments.
4. Submit a PR describing testing (at minimum, run the main menu flow on Windows).

## License
Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

## Support
- Open an issue on GitHub for bug reports or feature requests.
- For quick help, include PowerShell version, Windows build, and a transcript of the menu actions you ran.

