#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows provisioning bootstrap — fully touchless, idempotent, re-runnable.
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
$NeedsReboot = $false

# ── State Management ──────────────────────────────────────────────────────────

function Get-ProvisionState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile -Raw | ConvertFrom-Json
    }
    return [PSCustomObject]@{
        ctt_applied         = $false
        starship_configured = $false
        glazewm_configured  = $false
        pwsh_profile        = $false
        ssh_configured      = $false
        git_configured      = $false
        virtio_installed    = $false
        terminal_configured = $false
        last_run            = $null
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

    Write-Host "  Launching WinUtil with config (unattended)..." -ForegroundColor Yellow
    Write-Host "  This may take 10-30 min — installing apps and applying tweaks..." -ForegroundColor Yellow
    Write-Host "  WinUtil will be closed automatically when done." -ForegroundColor Yellow

    # Launch WinUtil in a background process using the official automation syntax.
    # WinUtil is a WPF GUI app — even with -Config -Run, it stays open after
    # completing tasks. We launch it async, then poll for completion and kill it.
    $powershellExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }
    $cttCommand = "& ([ScriptBlock]::Create((irm 'https://christitus.com/win'))) -Config '$configPath' -Run"
    $proc = Start-Process -FilePath $powershellExe -ArgumentList @(
        "-ExecutionPolicy", "Bypass",
        "-NoProfile",
        "-Command", $cttCommand
    ) -PassThru

    Write-Host "  WinUtil PID: $($proc.Id)" -ForegroundColor DarkGray

    # Poll for completion by watching the WinUtil log directory.
    # WinUtil writes logs to $env:LOCALAPPDATA\winutil\logs\winutil_*.log
    # When tasks finish, the log contains "Tweaks finished" / install completions.
    # We also watch for the GUI to go idle (MainWindowTitle changes, process becomes responsive).
    $logDir = "$env:LOCALAPPDATA\winutil\logs"
    $startTime = Get-Date
    $maxWaitMinutes = 60
    $lastStatus = ""

    while (!$proc.HasExited) {
        Start-Sleep -Seconds 15

        $elapsed = (Get-Date) - $startTime
        if ($elapsed.TotalMinutes -gt $maxWaitMinutes) {
            Write-Host "  [WARN] WinUtil exceeded ${maxWaitMinutes}m timeout — killing" -ForegroundColor Yellow
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            break
        }

        # Check the latest log file for completion signals
        $logFile = Get-ChildItem "$logDir\winutil_*.log" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1

        if ($logFile) {
            $logContent = Get-Content $logFile.FullName -Raw -ErrorAction SilentlyContinue
            if ($logContent) {
                # WinUtil logs these when all tasks are done
                $tweaksDone = $logContent -match "(?i)(Tweaks finished|Tweaks have been applied)"
                $installsDone = $logContent -match "(?i)(Install Done|Applications installed)"

                # Show progress
                $status = ""
                if ($logContent -match "(?i)installing.*?\.\.\.") { $status = "Installing apps..." }
                if ($logContent -match "(?i)applying tweaks") { $status = "Applying tweaks..." }
                if ($tweaksDone) { $status = "Tweaks complete." }
                if ($installsDone) { $status = "Installs complete." }

                if ($status -and $status -ne $lastStatus) {
                    Write-Host "  [$([math]::Floor($elapsed.TotalMinutes))m] $status" -ForegroundColor DarkGray
                    $lastStatus = $status
                }

                # If both installs and tweaks are done, give it a moment then close
                if ($tweaksDone -and $installsDone) {
                    Write-Host "  All WinUtil tasks completed — closing WinUtil..." -ForegroundColor Green
                    Start-Sleep -Seconds 5
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    break
                }
            }
        }

        # Fallback: if the log hasn't been written to in 3+ minutes AND we've been
        # running for at least 5 minutes, assume it's done (tasks completed, GUI idle)
        if ($logFile -and $elapsed.TotalMinutes -gt 5) {
            $logAge = (Get-Date) - $logFile.LastWriteTime
            if ($logAge.TotalMinutes -gt 3) {
                Write-Host "  WinUtil log inactive for 3+ min — assuming tasks complete, closing..." -ForegroundColor Yellow
                Start-Sleep -Seconds 3
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                break
            }
        }
    }

    # Wait for process to fully exit
    if (!$proc.HasExited) {
        $proc.WaitForExit(10000) | Out-Null
    }

    # Refresh PATH after installs (CTT runs in a child process with its own env)
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

    $script:NeedsReboot = $true
    $State.ctt_applied = $true
    Write-Done "CTT WinUtil"
    return $State
}

# ── Step 2: Starship Config ──────────────────────────────────────────────────

function Find-Starship {
    # Try Get-Command first (works if already in PATH)
    $cmd = Get-Command starship -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    # Refresh PATH from registry (CTT installs happen in a child process)
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    $cmd = Get-Command starship -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    # Check common install locations directly
    $candidates = @(
        "$env:ProgramFiles\starship\bin\starship.exe",
        "${env:ProgramFiles(x86)}\starship\bin\starship.exe",
        "$env:LOCALAPPDATA\Programs\starship\bin\starship.exe",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Starship.Starship_*\starship.exe",
        "$env:USERPROFILE\.cargo\bin\starship.exe",
        "C:\Program Files\starship\bin\starship.exe"
    )
    foreach ($pattern in $candidates) {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            # Add its directory to PATH for the rest of this session
            $binDir = Split-Path $found.FullName -Parent
            if ($env:Path -notlike "*$binDir*") {
                $env:Path = "$binDir;$env:Path"
                Write-Host "  Added $binDir to session PATH" -ForegroundColor DarkGray
            }
            return $found.FullName
        }
    }

    return $null
}

function Install-StarshipConfig {
    param($State)
    Write-Step "Starship Prompt Configuration"

    if ($State.starship_configured) {
        # Hash check for updates
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

    # Try to find starship (may have been installed by CTT)
    $starshipPath = Find-Starship
    if ($starshipPath) {
        Write-Host "  Found starship at: $starshipPath" -ForegroundColor DarkGray
    } else {
        Write-Host "  Starship not found — installing via winget..." -ForegroundColor Yellow
        try {
            $wingetOutput = & winget install --id Starship.Starship --accept-source-agreements --accept-package-agreements --silent 2>&1
            Write-Host "  winget output: $($wingetOutput | Out-String)" -ForegroundColor DarkGray
        } catch {
            Write-Host "  [WARN] winget install failed: $_" -ForegroundColor Yellow
        }

        # Refresh PATH and search again
        $starshipPath = Find-Starship
        if (!$starshipPath) {
            # Last resort: direct MSI/installer download
            Write-Host "  winget didn't work — trying direct installer..." -ForegroundColor Yellow
            try {
                $installerUrl = "https://github.com/starship/starship/releases/latest/download/starship-x86_64-pc-windows-msvc.msi"
                $installerPath = "$env:TEMP\starship-installer.msi"
                Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
                Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn" -Wait
                Remove-Item $installerPath -ErrorAction SilentlyContinue
                $starshipPath = Find-Starship
            } catch {
                Write-Host "  [WARN] Direct installer also failed: $_" -ForegroundColor Yellow
            }
        }

        if ($starshipPath) {
            Write-Host "  Starship installed: $starshipPath" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] Could not install starship — config will be deployed, will work after manual install or reboot" -ForegroundColor Yellow
            $script:NeedsReboot = $true
        }
    }

    # Deploy config regardless — even if starship binary isn't found yet,
    # the config will be ready when it is
    $dest = "$ConfigDir\starship.toml"
    Get-RepoFile -RepoPath "configs/starship/starship.toml" -Destination $dest
    Write-Host "  Deployed config to $dest"

    # Verify starship works if we found it
    if ($starshipPath) {
        try {
            $version = & $starshipPath --version 2>&1
            Write-Host "  Starship version: $version" -ForegroundColor DarkGray
        } catch {
            Write-Host "  [WARN] Starship binary found but failed to run: $_" -ForegroundColor Yellow
        }
    }

    $State.starship_configured = $true
    Write-Done "Starship config"
    return $State
}

# ── Step 3: GlazeWM & Zebar Config ──────────────────────────────────────────

function Install-GlazeWMConfig {
    param($State)
    Write-Step "GlazeWM & Zebar Configuration"

    if ($State.glazewm_configured) {
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

    $glazeDest = "$env:USERPROFILE\.glzr\glazewm\config.yaml"
    Get-RepoFile -RepoPath "configs/glazewm/config.yaml" -Destination $glazeDest
    Write-Host "  Deployed GlazeWM config"

    $zebarDir = "$env:USERPROFILE\.glzr\zebar"
    Get-RepoFile -RepoPath "configs/zebar/settings.json" -Destination "$zebarDir\settings.json"
    Get-RepoFile -RepoPath "configs/zebar/normalize.css" -Destination "$zebarDir\normalize.css"
    Write-Host "  Deployed Zebar configs"

    $State.glazewm_configured = $true
    Write-Done "GlazeWM & Zebar config"
    return $State
}

# ── Step 4: Windows Terminal Config ──────────────────────────────────────────

function Install-TerminalConfig {
    param($State)
    Write-Step "Windows Terminal Configuration"

    if ($State.terminal_configured) {
        Write-Skip "Windows Terminal config"
        return $State
    }

    # Find Windows Terminal settings path
    $wtPath = Get-ChildItem "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_*\LocalState" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (!$wtPath) {
        Write-Host "  Windows Terminal not found — skipping" -ForegroundColor Yellow
        return $State
    }

    $dest = Join-Path $wtPath.FullName "settings.json"
    Get-RepoFile -RepoPath "configs/terminal/settings.json" -Destination $dest
    Write-Host "  Deployed to $dest"

    $State.terminal_configured = $true
    Write-Done "Windows Terminal config"
    return $State
}

# ── Step 5: PowerShell Profile ───────────────────────────────────────────────

function Install-PwshProfile {
    param($State)
    Write-Step "PowerShell Profile"

    if ($State.pwsh_profile) {
        Write-Skip "PowerShell profile"
        return $State
    }

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

    # Deploy to both Windows PowerShell and PowerShell 7 profiles
    $profiles = @(
        $PROFILE.CurrentUserAllHosts
    )
    # Also check pwsh 7 profile location
    $pwsh7Profile = "$env:USERPROFILE\Documents\PowerShell\profile.ps1"
    $ps5Profile = "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1"
    $profiles = @($pwsh7Profile, $ps5Profile) | Select-Object -Unique

    foreach ($profilePath in $profiles) {
        $profileDir = Split-Path $profilePath -Parent
        if (!(Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir -Force | Out-Null }

        if (Test-Path $profilePath) {
            $existing = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
            if ($existing -match "starship init") {
                Write-Host "  Profile already configured: $profilePath" -ForegroundColor DarkGray
                continue
            }
            Add-Content -Path $profilePath -Value "`n# ── Added by win-provision ──`n$profileContent"
            Write-Host "  Appended to $profilePath"
        } else {
            Set-Content -Path $profilePath -Value $profileContent -Encoding UTF8
            Write-Host "  Created $profilePath"
        }
    }

    $State.pwsh_profile = $true
    Write-Done "PowerShell profile"
    return $State
}

# ── Step 6: OpenSSH Server ───────────────────────────────────────────────────

function Install-SSHServer {
    param($State)
    Write-Step "OpenSSH Server"

    if ($State.ssh_configured) {
        Write-Skip "OpenSSH Server"
        return $State
    }

    $sshd = Get-Service sshd -ErrorAction SilentlyContinue
    if ($sshd -and $sshd.Status -eq "Running") {
        Write-Host "  sshd already running"
        $State.ssh_configured = $true
        Write-Done "OpenSSH Server (already active)"
        return $State
    }

    $sshCapability = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"
    if ($sshCapability.State -ne "Installed") {
        Write-Host "  Installing OpenSSH Server..."
        Add-WindowsCapability -Online -Name $sshCapability.Name
        $script:NeedsReboot = $true
    }

    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd

    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if ($pwshPath) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $pwshPath -PropertyType String -Force | Out-Null
        Write-Host "  Default SSH shell set to PowerShell 7"
    }

    $rule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if (!$rule) {
        New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    }

    $State.ssh_configured = $true
    Write-Done "OpenSSH Server"
    return $State
}

# ── Step 7: Git Config ───────────────────────────────────────────────────────

function Install-GitConfig {
    param($State)
    Write-Step "Git Configuration"

    if ($State.git_configured) {
        Write-Skip "Git config"
        return $State
    }

    # Refresh PATH first (git may have been installed by CTT in child process)
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

    if (!(Get-Command git -ErrorAction SilentlyContinue)) {
        # Check common git install locations
        $gitPaths = @(
            "C:\Program Files\Git\cmd\git.exe",
            "C:\Program Files (x86)\Git\cmd\git.exe",
            "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe"
        )
        $gitFound = $gitPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($gitFound) {
            $gitDir = Split-Path $gitFound -Parent
            $env:Path = "$gitDir;$env:Path"
            Write-Host "  Found git at $gitFound — added to session PATH" -ForegroundColor DarkGray
        } else {
            Write-Host "  git not found — installing via winget..." -ForegroundColor Yellow
            try {
                & winget install --id Git.Git --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
            } catch {
                Write-Host "  [WARN] winget install failed: $_" -ForegroundColor Yellow
            }
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            if (!(Get-Command git -ErrorAction SilentlyContinue)) {
                Write-Host "  [WARN] Git still not found — will configure after reboot" -ForegroundColor Yellow
                $script:NeedsReboot = $true
                return $State
            }
        }
    }

    $currentName = git config --global user.name 2>$null
    if (!$currentName) {
        git config --global user.name "Anthony Mazzacca"
        Write-Host "  Git name set. Set email later: git config --global user.email you@example.com"
    } else {
        Write-Host "  Git already configured as: $currentName"
    }

    git config --global core.autocrlf true
    git config --global init.defaultBranch main

    $State.git_configured = $true
    Write-Done "Git config"
    return $State
}

# ── Step 8: VirtIO Guest Tools (VM only) ─────────────────────────────────────

function Install-VirtIO {
    param($State)
    Write-Step "VirtIO Guest Tools"

    if ($State.virtio_installed) {
        Write-Skip "VirtIO Guest Tools"
        return $State
    }

    $bios = (Get-CimInstance -ClassName Win32_BIOS).Manufacturer
    $system = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    $isVM = ($bios -match "QEMU|SeaBIOS|Bochs") -or ($system -match "QEMU")

    if (!$isVM) {
        Write-Host "  Not a QEMU/KVM VM — skipping" -ForegroundColor DarkGray
        $State.virtio_installed = $true
        return $State
    }

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

    $script:NeedsReboot = $true
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
    Write-Host "  User profile: $env:USERPROFILE" -ForegroundColor DarkGray
    if ($state.last_run) {
        Write-Host "  Last run: $($state.last_run)" -ForegroundColor DarkGray
    }

    # Test that we can actually write the state file
    try {
        Save-ProvisionState -State $state
        Write-Host "  State file writable: YES" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [ERROR] Cannot write state file: $_" -ForegroundColor Red
        Write-Host "  Provisioning state will not persist!" -ForegroundColor Red
    }

    $state = Invoke-CTTWinUtil -State $state
    Save-ProvisionState -State $state

    $state = Install-StarshipConfig -State $state
    Save-ProvisionState -State $state

    $state = Install-GlazeWMConfig -State $state
    Save-ProvisionState -State $state

    $state = Install-TerminalConfig -State $state
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

    if ($script:NeedsReboot) {
        Write-Host "  A reboot is required to finalize changes." -ForegroundColor Yellow
        Write-Host ""
        $response = Read-Host "  Reboot now? (Y/n)"
        if ($response -eq "" -or $response -eq "y" -or $response -eq "Y") {
            Write-Host "  Rebooting in 5 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            Restart-Computer -Force
        } else {
            Write-Host "  Skipped reboot. Remember to reboot before using the system." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  No reboot needed. System is ready." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "  Re-run anytime to pick up config changes:" -ForegroundColor DarkGray
    Write-Host "  irm https://raw.githubusercontent.com/tonypwns/win-provision/main/bootstrap.ps1 | iex" -ForegroundColor DarkGray
    Write-Host ""
}

Invoke-Provision
