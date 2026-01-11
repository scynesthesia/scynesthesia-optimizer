# Scynesthesia Optimizer v1.0 — Technical Reference

This document provides a technical and verifiable description of the logic implemented by Scynesthesia Optimizer v1.0 across its core modules. The approach is transparent: mechanisms, performance rationales, and associated security/compatibility trade-offs are explained explicitly.

## Core Engine (Security and Transactionality)

The base engine defines a per-run context object (`$Context`) to track changes, persist evidence of applied actions, and enable deterministic rollback. Transactionality relies on rollback action collections and a "transaction scope" mechanism for registry changes.

| Subsystem | Implementation (modules/functions) | Auditability and reversibility guarantee | Technical evidence |
| --- | --- | --- | --- |
| Per-run `$Context` | `New-RunContext`, `Get-RunContext` in `modules/core/context.psm1` | Centralizes run state (reboot required, rollback collections, tracking of non-registry changes and permission failures). Enables per-session traceability. | `RegistryRollbackActions`, `ServiceRollbackActions`, `NetshRollbackActions`, `NetworkHardwareRollbackActions`, `NonRegistryChanges` structures. |
| Registry rollback log | `Add-RegistryRollbackRecord`, `Invoke-RegistryRollback` in `modules/ui.psm1` | Captures value/key snapshots before modification and reverts in reverse order. | Captures `Path`, `Name`, `PreviousExists`, `PreviousValue` and applies reversal with error handling. |
| Registry transactions | `Invoke-RegistryTransaction` in `modules/core/context.psm1` | Delimits a block of changes; if any critical operation fails, it reverts changes within that block. | Uses the initial index of `RegistryRollbackActions`, detects failures, and rolls back in reverse order. |
| Rollback persistence | `Save-RollbackState`, `Restore-RollbackState` in `modules/core/context.psm1` | Persists changes to disk (JSON) for post-crash recovery. | File at `%ProgramData%\Scynesthesia\session_rollback.json` with `Registry/Services/Netsh/NetworkHardware`. |
| Non-registry changes | `Get-NonRegistryChangeTracker`, `Add-NonRegistryChange` in `modules/core/context.psm1` | Records changes to services, netsh, BCD, and PnP hardware for auditability and manual rollback. | `NonRegistryChanges` bucket with `ServiceState`, `NetshGlobal`, `HardwareDevices`, `BcdEdit` keys. |

**Technical summary:** the context behaves as a change ledger; rollback is reproducible because prior state is captured and can be persisted, while the transactional engine reverts any failed operation inside a registry block.

## Kernel & Security Hardening

This action set lives in `Invoke-KernelSecurityTweaks` and reduces kernel/ISR/DPC latency by disabling mitigations and adjusting timers. The module requires explicit confirmation due to security implications.

| Subsystem | Implementation (keys/commands) | Expected gain | Trade-off (risk) |
| --- | --- | --- | --- |
| Spectre/Meltdown mitigations | `FeatureSettingsOverride=3`, `FeatureSettingsOverrideMask=3` under `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management` | Lower overhead from side-channel mitigation paths in kernel transitions. | Exposure to Spectre/Meltdown-class attacks and reduced isolation between contexts. |
| VBS/HVCI | `EnableVirtualizationBasedSecurity=0` and `...\HypervisorEnforcedCodeIntegrity\Enabled=0` | Less hypervisor-enforced layering in kernel calls, reducing latency. | Disables virtualization-based isolation protections. |
| DEP | `DisableExecProtection=1` | Fewer execution checks, lower latency in some code paths. | Loss of data execution prevention. |
| ASLR | `MoveImages=0` | Avoids randomized relocation, reducing load/mapping cost. | Predictable address space for exploitation. |
| BCD timers | `bcdedit /set useplatformclock No`, `useplatformtick No`, `disabledynamictick Yes` | Reduced jitter and lower overhead from timers and dynamic ticks. | Potential timing compatibility issues on certain firmware/hardware. |

**Operational motivation:** the suite prioritizes a steep reduction in system-call latency (DPC/ISR), even at the cost of security, and explicitly surfaces the risk before applying changes.

## Modern Display Stack

The `Optimize-ModernDisplayModes` module applies FSO/MPO/WGO tweaks to maximize "exclusive-like" latency in windowed mode via *Independent Flip* when supported by the driver and OS.

| Subsystem | Implementation (keys/actions) | Expected gain | Trade-off |
| --- | --- | --- | --- |
| FSO (Fullscreen Optimizations) | `GameDVR_FSEBehaviorMode=0`, `GameDVR_HonorUserFSEBehaviorMode=1` under `HKCU:\System\GameConfigStore` | Lets windows use presentation paths closer to fullscreen without losing stable Alt+Tab. | Depends on user policy and system support. |
| WGO (Windowed Game Optimizations) | `DirectXUserGlobalSettings=VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;` under `HKCU:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences` | Forces flip-model presentation, enabling *Independent Flip* and lower render queueing. | Requires a modern graphics stack and recent drivers. |
| MPO (Multi-Plane Overlay) | Removal of `OverlayTestMode` under `HKLM:\SOFTWARE\Microsoft\Windows\Dwm` | Frees MPO for compositor overlays when they reduce latency. | Older drivers may flicker; requires stable WDDM 2.7+. |

**Operational note:** the module applies changes with rollback and marks `RebootRequired` to ensure full application after restart.

## NVIDIA Hardcore Tweaks

The `Invoke-NvidiaHardcoreTweaks` block hardens NVIDIA driver configuration to reduce micro-latency by eliminating DRM checks and power/telemetry overhead. The suite explicitly communicates risks.

| Subsystem | Implementation (keys/actions) | Expected gain | Trade-off |
| --- | --- | --- | --- |
| HDCP | `RMHdcpKeyGlobZero=1` in NVIDIA keys under `HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}` | Removes HDCP handshake checks that can cause micro-stutter. | Breaks protected content playback (Netflix, Disney+, Prime Video). |
| Write Combining | `DisableWriteCombining=1` under `HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm` | Reduces buffer-related stutter inside the driver. | May impact stability/performance, especially on older GPUs. |
| Telemetry/Power | `DisplayPowerSaving=0`, `OptInOrOutPreference=0`, disable tasks `NvTmRep/NvTmMon/NvDriverUpdateCheck` | Lowers background driver/control panel load. | Higher power consumption and loss of telemetry/diagnostics. |

## Hardware PnP Hardening

The `Invoke-HardwareDeviceHardening` module disables specific PnP devices by level (Safe/Aggressive/Gaming). At the aggressive level it includes HPET and WAN Miniports. Changes are recorded in the `HardwareDevices` tracker inside the context.

| Subsystem | Implementation (devices) | Expected gain | Trade-off |
| --- | --- | --- | --- |
| HPET | Disable `High Precision Event Timer` via `Disable-PnpDevice` | Reduces interrupt/timer sources considered redundant. | Legacy audio software may require HPET. |
| WAN Miniports | `WAN Miniport (IP/IPv6/L2TP/PPPOE/PPTP/SSTP/Network Monitor)` | Reduces IRQs and unused pseudo-network drivers in gaming environments. | Breaks VPN/PPPoE connectivity and legacy network tools. |

## Network Consistency

The networking adjustments target packet consistency and latency stability by reducing host-model ambiguity and segmentation variability.

| Subsystem | Implementation (keys/actions) | Expected gain | Trade-off |
| --- | --- | --- | --- |
| Weak Host Model | `Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled` on applicable adapters | More consistent routing decisions across interfaces, reducing path flaps that can manifest as jitter in multi-NIC scenarios. | May accept traffic on non-primary interfaces, increasing the need for strict interface hygiene. |
| UDP Segmentation Offload | `Set-NetAdapterAdvancedProperty -DisplayName "UDP Segmentation Offload" -DisplayValue "Disabled"` | More uniform packet sizing and pacing, reducing jitter caused by hardware segmentation variability. | Higher CPU load and lower peak throughput on some NICs. |

---

**Risk transparency:** all blocks above request interactive confirmation and record changes for audit/rollback, prioritizing performance over security when the operator explicitly accepts the trade-offs.
