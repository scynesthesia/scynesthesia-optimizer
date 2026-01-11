# Scynesthesia Optimizer v1.0 — Technical Reference

This document provides a technical, verifiable description of Scynesthesia Optimizer v1.0 across its core modules. The intent is transparency: mechanisms, performance rationale, and security/compatibility trade-offs are spelled out in operational terms.

## Core Engine (Security and Transactionality)

**Tweak:** Per-run `$Context` ledger.
**Justification:** Tracks state before and after changes so rollback is deterministic. This does not reduce DPC/ISR directly, but it prevents partial writes that can leave the system in an inconsistent latency state after failures or reboots.
**Trade-off:** Slight runtime overhead from bookkeeping and JSON persistence.

**Tweak:** Registry rollback log (`Add-RegistryRollbackRecord`, `Invoke-RegistryRollback`).
**Justification:** Captures values and existence state before mutation so registry writes can be reverted in reverse order. This keeps kernel and driver state transitions coherent when tuning high-impact keys.
**Trade-off:** Adds disk writes and more log data to manage.

**Tweak:** Registry transaction scope (`Invoke-RegistryTransaction`).
**Justification:** Uses a local rollback boundary so failed registry operations are reverted immediately, preventing half-applied driver or kernel paths that can surface as jitter.
**Trade-off:** Stops the preset when critical steps fail, which can reduce coverage in partial runs.

**Tweak:** Rollback persistence (`Save-RollbackState`, `Restore-RollbackState`).
**Justification:** Persists the rollback ledger to `%ProgramData%\Scynesthesia\session_rollback.json` so crash recovery does not leave low-level settings stranded.
**Trade-off:** Requires writable system storage; failure to persist is treated as a hard stop for safety.

**Tweak:** Non-registry change tracking (`Add-NonRegistryChange`).
**Justification:** Records netsh, service, BCD, and hardware changes so operators can explicitly unwind non-registry state that impacts DPC/ISR behavior.
**Trade-off:** Manual rollback for non-registry changes still requires operator intent.

## Kernel & Security Hardening

**Tweak:** Spectre/Meltdown mitigation overrides (`FeatureSettingsOverride=3`, `FeatureSettingsOverrideMask=3`).
**Justification:** Removes speculative execution mitigation paths in kernel transitions, lowering branch fencing and context switch cost that surfaces in DPC/ISR latency.
**Trade-off:** Exposes the system to Spectre/Meltdown-class side-channel attacks.

**Tweak:** VBS/HVCI disablement (`EnableVirtualizationBasedSecurity=0`, `HypervisorEnforcedCodeIntegrity=0`).
**Justification:** Removes hypervisor-enforced indirection in kernel execution, reducing ISR/DPC overhead in code integrity checks.
**Trade-off:** Loses virtualization-based isolation protections.

**Tweak:** DEP disablement (`DisableExecProtection=1`).
**Justification:** Reduces execution-check overhead in some kernel paths, lowering latency for drivers that thrash DEP checks during high ISR load.
**Trade-off:** Lowers memory execution safety.

**Tweak:** ASLR disablement (`MoveImages=0`).
**Justification:** Avoids relocation churn for driver images, reducing initialization overhead and loader work in the kernel path.
**Trade-off:** Predictable address layout increases exploitability.

**Tweak:** BCD timer policy (`bcdedit /set useplatformclock No`, `useplatformtick No`, `disabledynamictick Yes`).
**Justification:** Forces a stable timing source and disables dynamic ticks to reduce scheduling jitter that can bleed into audio and render DPCs.
**Trade-off:** Firmware-specific timing compatibility issues are possible.

## Modern Display Stack

**Tweak:** FSO policy (`GameDVR_FSEBehaviorMode=0`, `GameDVR_HonorUserFSEBehaviorMode=1`).
**Justification:** Encourages flip-model presentation paths closer to exclusive fullscreen, reducing composition overhead and latency in the graphics pipeline.
**Trade-off:** Behavior depends on the GPU driver and OS build.

**Tweak:** WGO policy (`DirectXUserGlobalSettings=VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;`).
**Justification:** Forces flip-model presentation to unlock Independent Flip where supported, trimming compositor queueing and reducing frame pacing jitter.
**Trade-off:** Requires modern WDDM drivers and compatible display paths.

**Tweak:** MPO unlock (removing `OverlayTestMode`).
**Justification:** Enables multi-plane overlay paths that can bypass parts of the compositor, reducing GPU scheduling overhead that shows up in frametime spikes.
**Trade-off:** Older drivers may flicker or mis-handle overlays.

## NVIDIA Hardcore Tweaks

**Tweak:** HDCP disablement (`RMHdcpKeyGlobZero=1`).
**Justification:** Removes HDCP handshake checks that can inject periodic driver stalls, improving consistent render and capture timing.
**Trade-off:** Protected content playback and DRM authentication can fail.

**Tweak:** Write combining disablement (`DisableWriteCombining=1`).
**Justification:** Limits driver-side buffering strategies that can introduce bursty present behavior and micro-stutter under load.
**Trade-off:** Possible performance regressions or instability on some GPUs.

**Tweak:** Telemetry/power throttling removal (`DisplayPowerSaving=0`, `OptInOrOutPreference=0`, disable tasks `NvTmRep/NvTmMon/NvDriverUpdateCheck`).
**Justification:** Cuts background driver polling and state transitions that can preempt render threads and inflate ISR/DPC noise.
**Trade-off:** Higher power draw and less driver diagnostics.

## Hardware PnP Hardening

**Tweak:** HPET disablement (`Disable-PnpDevice` on `High Precision Event Timer`).
**Justification:** Reduces redundant timer sources competing for scheduler attention, lowering jitter in high-frequency audio or input ISR workloads.
**Trade-off:** Some legacy audio stacks require HPET for stability.

**Tweak:** WAN Miniport disablement (`WAN Miniport (IP/IPv6/L2TP/PPPOE/PPTP/SSTP/Network Monitor)`).
**Justification:** Removes unused pseudo-NIC drivers that can register interrupts and driver callbacks, trimming kernel bookkeeping overhead.
**Trade-off:** Breaks VPN/PPPoE connectivity and legacy network tooling.

## Network Consistency

**Tweak:** Weak Host Model enablement (`Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled`).
**Justification:** Reduces logical friction in the IP stack by allowing interfaces to accept and forward traffic more flexibly, minimizing routing flips that can present as jitter in multi-NIC and virtual adapter layouts.
**Trade-off:** More permissive interface behavior increases the need for strict firewall and adapter hygiene.

**Tweak:** UDP Segmentation Offload disablement (`Set-NetAdapterAdvancedProperty -DisplayName "UDP Segmentation Offload" -DisplayValue "Disabled"`).
**Justification:** Shifts segmentation from NIC hardware back to the stack to reduce interrupt bursts and DPC spikes caused by large offloaded UDP frames.
**Trade-off:** Higher CPU usage and lower peak throughput on some adapters.

---

**Risk transparency:** all blocks above request interactive confirmation and record changes for audit/rollback, prioritizing performance over security when the operator explicitly accepts the trade-offs.
