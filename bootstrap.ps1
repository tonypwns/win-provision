#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows provisioning bootstrap — idempotent, re-runnable.
.DESCRIPTION
    Pulls config from GitHub and provisions a fresh Windows install.
    Tracks state in ~/.provision-state.json to skip completed steps.
    Safe to re-run — only does what's missing.
.NOTES
    One-liner: irm https://raw.githubusercontent.com/tonypwns/win-provision/main/bootstrap.ps1 | iex
#>

$ErrorActionPreference = "Stop"
$RepoBase = "https://raw.githubusercontent.com/tonypwns/win-provision/main"
$StateFile = "$env:USERPROFILE\.provision-state.json"
$ConfigDir = "$env:USERPROFILE\.config"

# ── State Management ──────────────────────────────────────────────────────────

function Get-ProvisionState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile -Raw | ConvertFrom-Json
    }
    return [PSCustomObject]@{
        ctt_applied        = $false
        starship_configured = $false
        glazewm_configured = $false
        pwsh_profile       = $false
        ssh_configured     = $false
        git_configured     = $false
        virtio_installed   = $false
        last_run           = $null
    }
}

function Save-ProvisionState {
    param($State)
    $State.last_run = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $State | ConvertTo-Json -Depth 3 | Set-Content $StateFile -Encoding UTF8
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Skip {
    param([string]$Message)
    Write-Host "  [SKIP] $Message — already completed" -ForegroundColor DarkGray
}

function Write-Done {
    param([string]$Message)
    Write-Host "  [DONE] $Message" -ForegroundColor Green
}

# ── Helper: Download file from repo ───────────────────────────────────────────

function Get-RepoFile {
    param(
        [string]$RepoPath,
        [string]$Destination
    )
    $url = "$RepoBase/$RepoPath"
    $destDir = Split-Path $Destination -Parent
    if (!(Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    Invoke-RestMethod -Uri $url -OutFile $Destination
}

# ── Step 1: CTT WinUtil ──────────────────────────────────────────────────────

function Invoke-CTTWinUtil {
    param($State)
    Write-Step "CTT WinUtil — Apps, Tweaks & Features"

    if ($State.ctt_applied) {
        Write-Skip "CTT WinUtil"
        return $State
    }

    # Download config
    $configPath = "$env:TEMP\CTT_config.json"
    Get-RepoFile -RepoPath "CTT_config.json" -Destination $configPath
    Write-Host "  Config downloaded to $configPath"

    # Verify apps aren't already installed (spot-check a few key ones)
    $spotCheck = @("starship", "alacritty", "pwsh")
    $installed = 0
    foreach ($cmd in $spotCheck) {
        if (Get-Command $cmd -ErrorAction SilentlyContinue) { $installed++ }
    }

    if ($installed -ge 2) {
        Write-Host "  Most apps appear already installed ($installed/3 spot-check passed)" -ForegroundColor Yellow
        $State.ctt_applied = $true
        Write-Done "Skipped — apps already present"
        return $State
    }

    Write-Host "  Running WinUtil with config (unattended)..." -ForegroundColor Yellow
    iex "& { $(irm christitus.com/win) } -Config `"$configPath`" -Run"

    $State.ctt_applied = $true
    Write-Done "CTT WinUtil"
    return $State
}

# ── Step 2: Starship Config ──────────────────────────────────────────────────

function Install-StarshipConfig {
    param($State)
    Write-Step "Starship Prompt Configuration"

    if ($State.starship_configured) {
        # Check if config has changed upstream
        $dest = "$ConfigDir\starship.toml"
        if (Test-Path $dest) {
            $current = Get-FileHash $dest -Algorithm SHA256
            $tempFile = "$env:TEMP\starship-check.toml"
            try {
                Get-RepoFile -RepoPath "configs/starship/starship.toml" -Destination $tempFile
                $upstream = Get-FileHash $tempFile -Algorithm SHA256
                if ($current.Hash -eq $upstream.Hash) {
                    Write-Skip "Starship config (up to date)"
                    return $State
                }
                Write-Host "  Config has changed upstream — updating" -ForegroundColor Yellow
            } catch {
                Write-Skip "Starship config (couldn't check upstream)"
                return $State
            }
        } else {
            Write-Host "  Config file missing — re-deploying" -ForegroundColor Yellow
        }
    }

    if (!(Get-Command starship -ErrorAction SilentlyContinue)) {
        Write-Host "  Starship not installed — install via CTT WinUtil first" -ForegroundColor Red
        return $State
    }

    $dest = "$ConfigDir\starship.toml"
    Get-RepoFile -RepoPath "configs/starship/starship.toml" -Destination $dest
    Write-Host "  Deployed to $dest"

    $State.starship_configured = $true
    Write-Done "Starship config"
    return $State
}

# ── Step 2b: GlazeWM & Zebar Config ──────────────────────────────────────────

function Install-GlazeWMConfig {
    param($State)
    Write-Step "GlazeWM & Zebar Configuration"

    if ($State.glazewm_configured) {
        # Hash check for updates
        $glazeConf = "$env:USERPROFILE\.glzr\glazewm\config.yaml"
        if (Test-Path $glazeConf) {
            $current = Get-FileHash $glazeConf -Algorithm SHA256
            $tempFile = "$env:TEMP\glazewm-check.yaml"
            try {
                Get-RepoFile -RepoPath "configs/glazewm/config.yaml" -Destination $tempFile
                $upstream = Get-FileHash $tempFile -Algorithm SHA256
                if ($current.Hash -eq $upstream.Hash) {
                    Write-Skip "GlazeWM & Zebar config (up to date)"
                    return $State
                }
                Write-Host "  Config has changed upstream — updating" -ForegroundColor Yellow
            } catch {
                Write-Skip "GlazeWM & Zebar config (couldn't check upstream)"
                return $State
            }
        }
    }

    # Deploy GlazeWM config
    $glazeDest = "$env:USERPROFILE\.glzr\glazewm\config.yaml"
    Get-RepoFile -RepoPath "configs/glazewm/config.yaml" -Destination $glazeDest
    Write-Host "  Deployed GlazeWM config to $glazeDest"

    # Deploy Zebar configs
    $zebarDir = "$env:USERPROFILE\.glzr\zebar"
    Get-RepoFile -RepoPath "configs/zebar/settings.json" -Destination "$zebarDir\settings.json"
    Get-RepoFile -RepoPath "configs/zebar/normalize.css" -Destination "$zebarDir\normalize.css"
    Write-Host "  Deployed Zebar configs to $zebarDir"

    $State.glazewm_configured = $true
    Write-Done "GlazeWM & Zebar config"
    return $State
}

# ── Step 3: PowerShell Profile ───────────────────────────────────────────────

function Install-PwshProfile {
    param($State)
    Write-Step "PowerShell Profile"

    if ($State.pwsh_profile) {
        Write-Skip "PowerShell profile"
        return $State
    }

    # Determine profile path (prefer pwsh 7 over Windows PowerShell)
    $profilePath = $PROFILE.CurrentUserAllHosts

    $profileContent = @'
# ── Starship Prompt ──
if (Get-Command starship -ErrorAction SilentlyContinue) {
    Invoke-Expression (&starship init powershell)
}

# ── Aliases ──
Set-Alias -Name which -Value Get-Command
Set-Alias -Name touch -Value New-Item
function ll { Get-ChildItem -Force @args }
function .. { Set-Location .. }
function ... { Set-Location ..\.. }

# ── SSH Agent ──
if (Get-Service ssh-agent -ErrorAction SilentlyContinue | Where-Object Status -eq Running) {
    $env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"
}
'@

    $profileDir = Split-Path $profilePath -Parent
    if (!(Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir -Force | Out-Null }

    # Don't clobber existing profile — append if it exists
    if (Test-Path $profilePath) {
        $existing = Get-Content $profilePath -Raw
        if ($existing -match "starship init") {
            Write-Host "  Profile already contains starship init — skipping" -ForegroundColor Yellow
            $State.pwsh_profile = $true
            return $State
        }
        Write-Host "  Appending to existing profile at $profilePath"
        Add-Content -Path $profilePath -Value "`n# ── Added by win-provision ──`n$profileContent"
    } else {
        Set-Content -Path $profilePath -Value $profileContent -Encoding UTF8
        Write-Host "  Created profile at $profilePath"
    }

    $State.pwsh_profile = $true
    Write-Done "PowerShell profile"
    return $State
}

# ── Step 4: OpenSSH Server ───────────────────────────────────────────────────

function Install-SSHServer {
    param($State)
    Write-Step "OpenSSH Server"

    if ($State.ssh_configured) {
        Write-Skip "OpenSSH Server"
        return $State
    }

    # Check if already running
    $sshd = Get-Service sshd -ErrorAction SilentlyContinue
    if ($sshd -and $sshd.Status -eq "Running") {
        Write-Host "  sshd already running"
        $State.ssh_configured = $true
        Write-Done "OpenSSH Server (already active)"
        return $State
    }

    # Install OpenSSH Server capability
    $sshCapability = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"
    if ($sshCapability.State -ne "Installed") {
        Write-Host "  Installing OpenSSH Server..."
        Add-WindowsCapability -Online -Name $sshCapability.Name
    }

    # Configure and start
    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd

    # Set PowerShell 7 as default shell (if available)
    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if ($pwshPath) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $pwshPath -PropertyType String -Force | Out-Null
        Write-Host "  Default SSH shell set to PowerShell 7"
    }

    # Firewall rule
    $rule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if (!$rule) {
        New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    }

    $State.ssh_configured = $true
    Write-Done "OpenSSH Server"
    return $State
}

# ── Step 5: Git Config ───────────────────────────────────────────────────────

function Install-GitConfig {
    param($State)
    Write-Step "Git Configuration"

    if ($State.git_configured) {
        Write-Skip "Git config"
        return $State
    }

    if (!(Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "  git not found — skipping" -ForegroundColor Yellow
        return $State
    }

    $currentName = git config --global user.name 2>$null
    if (!$currentName) {
        git config --global user.name "Anthony Mazzacca"
        Write-Host "  Git name set. Configure email later: git config --global user.email you@example.com"
    } else {
        Write-Host "  Git already configured as: $currentName"
    }

    git config --global core.autocrlf true
    git config --global init.defaultBranch main

    $State.git_configured = $true
    Write-Done "Git config"
    return $State
}

# ── Step 6: VirtIO Guest Tools (VM only) ─────────────────────────────────────

function Install-VirtIO {
    param($State)
    Write-Step "VirtIO Guest Tools"

    if ($State.virtio_installed) {
        Write-Skip "VirtIO Guest Tools"
        return $State
    }

    # Detect if running in a QEMU/KVM VM
    $bios = (Get-CimInstance -ClassName Win32_BIOS).Manufacturer
    $system = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    $isVM = ($bios -match "QEMU|SeaBIOS|Bochs") -or ($system -match "QEMU")

    if (!$isVM) {
        Write-Host "  Not a QEMU/KVM VM — skipping" -ForegroundColor DarkGray
        $State.virtio_installed = $true
        return $State
    }

    # Check if guest agent is already running
    $qga = Get-Service QEMU-GA -ErrorAction SilentlyContinue
    if ($qga -and $qga.Status -eq "Running") {
        Write-Host "  QEMU Guest Agent already running"
        $State.virtio_installed = $true
        Write-Done "VirtIO (already installed)"
        return $State
    }

    Write-Host "  QEMU/KVM VM detected — installing VirtIO guest tools..." -ForegroundColor Yellow
    $installerUrl = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win-guest-tools.exe"
    $installerPath = "$env:TEMP\virtio-win-guest-tools.exe"
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
    Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait

    $State.virtio_installed = $true
    Write-Done "VirtIO Guest Tools"
    return $State
}

# ── Main ─────────────────────────────────────────────────────────────────────

function Invoke-Provision {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   Windows Provisioning Bootstrap     ║" -ForegroundColor Cyan
    Write-Host "  ║   github.com/tonypwns/win-provision  ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Cyan

    $state = Get-ProvisionState
    Write-Host "`n  State file: $StateFile"
    if ($state.last_run) {
        Write-Host "  Last run: $($state.last_run)" -ForegroundColor DarkGray
    }

    $state = Invoke-CTTWinUtil -State $state
    Save-ProvisionState -State $state

    $state = Install-StarshipConfig -State $state
    Save-ProvisionState -State $state

    $state = Install-GlazeWMConfig -State $state
    Save-ProvisionState -State $state

    $state = Install-PwshProfile -State $state
    Save-ProvisionState -State $state

    $state = Install-SSHServer -State $state
    Save-ProvisionState -State $state

    $state = Install-GitConfig -State $state
    Save-ProvisionState -State $state

    $state = Install-VirtIO -State $state
    Save-ProvisionState -State $state

    Write-Host ""
    Write-Step "Provisioning Complete"
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "    1. Install NordPass and log in"
    Write-Host "    2. Configure terminal (Alacritty/Windows Terminal)"
    Write-Host "    3. Reboot to apply all changes"
    Write-Host ""
    Write-Host "  Re-run anytime to pick up changes:" -ForegroundColor DarkGray
    Write-Host "  irm https://raw.githubusercontent.com/tonypwns/win-provision/main/bootstrap.ps1 | iex" -ForegroundColor DarkGray
    Write-Host ""
}

Invoke-Provision
