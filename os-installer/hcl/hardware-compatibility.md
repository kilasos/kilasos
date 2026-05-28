# Hardware Compatibility List (HCL)

| Category | Model | Notes |
|----------|-------|-------|
| **Motherboards** | ASRock B550M Pro4 | Verified boot and data disk support; ZFS works out-of-box |
| | Supermicro X12SPA | Supports NVMe boot; tested with ZFS root |
| | Gigabyte Aorus Elite AX (Z690) | Requires BIOS update; ZFS boot confirmed |
| | ASRock Z790 ProRS | Works with ZFS only when UEFI mode enforced |
| **HBAs** | LSI 9211-8i (FW 14.00.00.00) | IT mode required; fully compatible |
| | LSI 9300-8i | Plug-and-play; no firmware tweaks needed |
| | HP H220 (rev 2.0) | IT mode flash required; verified with OpenZFS |
| **NICs** | Intel I210-T1 | Stable on-board; no driver issues |
| | Intel I350-T2 | Works reliably; confirmed in lab |
| | Realtek 8111G | Functional but avoid sustained high throughput |
| **SBCs** | Raspberry Pi 4 (4GB RAM) | Boot from microSD; ZFS on USB/SSD supported |
| | Raspberry Pi 5 (8GB RAM) | Requires 64-bit OS; ZFS root tested on 6.6+ kernel |
| **Minimum Specs** | CPU: 2 cores (x86_64/ARM64) | ARM: Cortex-A72+ recommended |
| | RAM: 2GB minimum | 4GB+ recommended for ZFS ARC |
| | Boot disk: 8GB (USB/microSD/eMMC) | Must be UEFI-compliant for UEFI boot |
| | Data disk: ≥1 (SATA/NVMe/USB) | ZFS pool requires dedicated disk |

> **Notes**:  
- ZFS support requires kernel ≥5.15 or FreeBSD 13+; avoid legacy BIOS unless verified.  
- HBAs must be flashed to IT mode; OEM firmware may block passthrough.  
- Raspberry Pi support is experimental; use official Raspberry Pi OS or Ubuntu 22.04+ ARM64.  
- Intel NICs preferred for reliability; Realtek may cause latency spikes under load.  
- All tested with OpenZFS 2.2.2 and FreeBSD 14.0-RELEASE.
