# Scynesthesia Optimizer v1.0 — Technical Reference

Este documento describe, de forma técnica y verificable, la lógica que implementa Scynesthesia Optimizer v1.0 en sus módulos principales. El enfoque es transparente: se explican mecanismos, justificaciones de rendimiento y los trade-offs de seguridad/compatibilidad asociados.

## Core Engine (Seguridad y Transaccionalidad)

El motor base define un objeto de contexto por ejecución (`$Context`) para rastrear cambios, persistir evidencia de lo aplicado y habilitar rollback determinista. La transaccionalidad se apoya en colecciones de acciones de reversión y en un mecanismo de “transaction scope” para cambios de registro.

| Subsistema | Implementación (módulos/funciones) | Garantía de auditoría y reversibilidad | Evidencia técnica |
| --- | --- | --- | --- |
| `$Context` por ejecución | `New-RunContext`, `Get-RunContext` en `modules/core/context.psm1` | Centraliza estado de ejecución (reboot requerido, colecciones de rollback, tracking de cambios no-registro y fallos de permisos). Facilita trazabilidad por sesión. | Estructuras `RegistryRollbackActions`, `ServiceRollbackActions`, `NetshRollbackActions`, `NetworkHardwareRollbackActions`, `NonRegistryChanges`. | 
| Registro de rollback de registro | `Add-RegistryRollbackRecord`, `Invoke-RegistryRollback` en `modules/ui.psm1` | Registra la fotografía de valor/clave antes de la modificación y permite revertir en orden inverso. | Captura `Path`, `Name`, `PreviousExists`, `PreviousValue` y ejecuta reversión con manejo de errores. |
| Transacciones de registro | `Invoke-RegistryTransaction` en `modules/core/context.psm1` | Delimita un bloque de cambios; si cualquier operación crítica falla, revierte los cambios de ese bloque. | Usa índice inicial de `RegistryRollbackActions`, detecta fallos y revierte en orden inverso. |
| Persistencia de rollback | `Save-RollbackState`, `Restore-RollbackState` en `modules/core/context.psm1` | Persiste cambios a disco (JSON) para recuperación post-crash. | Archivo en `%ProgramData%\Scynesthesia\session_rollback.json` con `Registry/Services/Netsh/NetworkHardware`. |
| Cambios no-registro | `Get-NonRegistryChangeTracker`, `Add-NonRegistryChange` en `modules/core/context.psm1` | Registra cambios de servicios, netsh, BCD y hardware PnP para auditoría y eventual reversión manual. | Bucket `NonRegistryChanges` con claves `ServiceState`, `NetshGlobal`, `HardwareDevices`, `BcdEdit`. |

**Resumen técnico:** el contexto funciona como “ledger” de cambios; el rollback es reproducible porque captura el estado anterior y puede persistirse, mientras que el motor transaccional revierte cualquier operación fallida dentro de un bloque de registro.

## Kernel & Security Hardening

Este conjunto de acciones reside en `Invoke-KernelSecurityTweaks` y reduce latencias de kernel/ISR/DPC mediante desactivación de mitigaciones y ajustes de timer. El módulo solicita confirmación explícita debido a las implicaciones de seguridad.

| Subsistema | Implementación (claves / comandos) | Justificación (latencia) | Trade-off (riesgo) |
| --- | --- | --- | --- |
| Mitigaciones Spectre/Meltdown | `FeatureSettingsOverride=3`, `FeatureSettingsOverrideMask=3` en `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management` | Reduce overhead de mitigaciones de canal lateral en transiciones de kernel. | Exposición a ataques Spectre/Meltdown y disminución de aislamiento entre contextos. |
| VBS/HVCI | `EnableVirtualizationBasedSecurity=0` y `...\HypervisorEnforcedCodeIntegrity\Enabled=0` | Reduce virtualización forzada en llamadas al kernel (menos “layering” en seguridad). | Se desactiva aislamiento basado en hipervisor. |
| DEP | `DisableExecProtection=1` | Menos checks de ejecución, menor latencia en ciertos caminos. | Pérdida de mitigación de ejecución de datos. |
| ASLR | `MoveImages=0` | Evita relocalización aleatoria, reduce costo de carga/mapeo. | Espacio de direcciones más predecible para explotación. |
| BCD timers | `bcdedit /set useplatformclock No`, `useplatformtick No`, `disabledynamictick Yes` | Reduce jitter y overhead de timers y ticks dinámicos. | Potencial impacto en compatibilidad temporal en hardware/firmware particulares. |

**Motivación operacional:** la suite prioriza la reducción drástica de latencia de llamadas al sistema (DPC/ISR), incluso al costo de seguridad, explicitando el riesgo al operador antes de aplicar los cambios.

## Modern Display Stack

El módulo `Optimize-ModernDisplayModes` aplica ajustes de FSO/MPO/WGO para maximizar la latencia “exclusive-like” en modo ventana mediante el modelo de *Independent Flip* cuando el driver y el SO lo permiten.

| Subsistema | Implementación (claves / acciones) | Justificación | Trade-off |
| --- | --- | --- | --- |
| FSO (Fullscreen Optimizations) | `GameDVR_FSEBehaviorMode=0`, `GameDVR_HonorUserFSEBehaviorMode=1` en `HKCU:\System\GameConfigStore` | Permite que ventanas aprovechen rutas de presentación más cercanas a fullscreen sin perder Alt+Tab estable. | Depende del soporte y políticas del sistema por usuario. |
| WGO (Windowed Game Optimizations) | `DirectXUserGlobalSettings=VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;` en `HKCU:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences` | Fuerza actualización del modelo de presentación hacia *flip model*, habilitando *Independent Flip* y menor cola de render. | Necesita soporte moderno del stack gráfico y drivers recientes. |
| MPO (Multi-Plane Overlay) | Eliminación de `OverlayTestMode` en `HKLM:\SOFTWARE\Microsoft\Windows\Dwm` | Libera MPO para que el compositor utilice overlays cuando aporta menor latencia. | Drivers antiguos pueden presentar flickering; requiere estabilidad WDDM 2.7+. |

**Nota operativa:** el módulo aplica cambios con rollback, y marca `RebootRequired` para garantizar aplicación completa tras reinicio.

## NVIDIA Hardcore Tweaks

El bloque `Invoke-NvidiaHardcoreTweaks` endurece la configuración del driver NVIDIA para reducir micro-latencias, eliminando protecciones DRM y ajustes de ahorro de energía/telemetría. La suite informa explícitamente de riesgos.

| Subsistema | Implementación (claves / acciones) | Justificación | Trade-off |
| --- | --- | --- | --- |
| HDCP | `RMHdcpKeyGlobZero=1` en claves NVIDIA bajo `HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}` | Elimina chequeos HDCP que pueden causar micro-stutter durante handshake DRM. | Rompe reproducción de contenido protegido (Netflix, Disney+, Prime Video). |
| Write Combining | `DisableWriteCombining=1` en `HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm` | Evita escritura combinada en el driver, mitigando stutter por buffers. | Puede afectar estabilidad/rendimiento, especialmente en GPUs antiguas. |
| Telemetría/Power | `DisplayPowerSaving=0`, `OptInOrOutPreference=0`, tareas `NvTmRep/NvTmMon/NvDriverUpdateCheck` deshabilitadas | Reduce carga de fondo en driver/control panel. | Mayor consumo energético y pérdida de telemetría/diagnóstico. |

## Hardware PnP Hardening

El módulo `Invoke-HardwareDeviceHardening` deshabilita dispositivos PnP específicos por nivel (Safe/Aggressive/Gaming). En el nivel agresivo se incluyen HPET y WAN Miniports. Los cambios se registran en el tracker de `HardwareDevices` dentro del contexto.

| Subsistema | Implementación (dispositivos) | Justificación | Trade-off |
| --- | --- | --- | --- |
| HPET | Deshabilita `High Precision Event Timer` vía `Disable-PnpDevice` | Reduce interrupciones y timers de hardware considerados redundantes. | Software de audio antiguo puede requerir HPET. |
| WAN Miniports | `WAN Miniport (IP/IPv6/L2TP/PPPOE/PPTP/SSTP/Network Monitor)` | Reduce IRQs y drivers pseudo-red no usados en entornos gaming. | Rompe conectividad VPN/PPPoE y herramientas de red heredadas. |

---

**Transparencia de riesgos:** todos los bloques anteriores exponen confirmaciones interactivas y registran cambios para auditoría/rollback, priorizando rendimiento sobre seguridad cuando el operador lo acepta explícitamente.
