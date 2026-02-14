# win-provision

Windows provisioning bootstrap — idempotent, re-runnable.

## Quick Start

Open PowerShell **as Administrator** and run:

```powershell
irm https://raw.githubusercontent.com/tonypwns/win-provision/main/bootstrap.ps1 | iex
```

## What It Does

| Step | Description | Idempotency |
|------|-------------|-------------|
| **CTT WinUtil** | 29 apps, 21 debloat tweaks, 3 Windows features | Spot-checks installed apps, prompts if already done |
| **Starship** | Deploys prompt config to `~/.config/starship.toml` | Hash comparison — only updates if changed |
| **PowerShell Profile** | Starship init, aliases, SSH agent | Checks for existing starship init before appending |
| **OpenSSH Server** | Installs, enables, sets pwsh as default shell | Checks service status before touching |
| **Git Config** | Sets name, email, autocrlf, default branch | Checks existing config before prompting |
| **VirtIO Guest Tools** | Installs QEMU guest agent (VMs only) | Detects QEMU/KVM, checks if agent is running |

## State Tracking

Progress is saved to `~/.provision-state.json`. Each step checks this file before running. Safe to re-run anytime — only incomplete steps execute.

## Files

```
├── bootstrap.ps1                  # Main provisioning script
├── CTT_config.json                # WinUtil app/tweak/feature selections
├── configs/
│   └── starship/starship.toml     # Prompt configuration
└── README.md
```

## Customizing

- **Apps/Tweaks:** Edit `CTT_config.json` (export from WinUtil GUI)
- **Starship prompt:** Edit `configs/starship/starship.toml`
- **Reset state:** Delete `~/.provision-state.json` to re-run everything
