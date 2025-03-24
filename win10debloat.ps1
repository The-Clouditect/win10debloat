function Set-ChromeDefault {
    Write-Status "Setting Chrome as default browser..."
    
    try {
        # Prepare Chrome registry entries
        $progId = "ChromeHTML"
        
        # Set default protocol handlers for HTTP/HTTPS
        $protoPath = "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations"
        $protocols = @("http", "https")
        
        foreach ($protocol in $protocols) {
            $protocolPath = "$protoPath\$protocol\UserChoice"
            
            # We can try but Windows often reverts these
            if (!(Test-Path $protocolPath)) {
                if (!$DryRun) {
                    New-Item -Path $protocolPath -Force | Out-Null
                } else {
                    Write-WouldPerform "Create registry path $protocolPath"
                }
            }
            
            try {
                if (!$DryRun) {
                    Set-ItemProperty -Path $protocolPath -Name "ProgId" -Value $progId -Type String -Force
                    Write-Success "Set Chrome as default for $protocol (may require user confirmation)"
                } else {
                    Write-WouldPerform "Set Chrome as default for $protocol protocol"
                }
            } catch {
                # Windows 10 actively prevents programmatic changes here
                Write-Warning "Could not set Chrome as default for $protocol protocol"
            }
        }
        
        # Set default file associations
        $fileTypes = @(".htm", ".html")
        foreach ($type in $fileTypes) {
            try {
                if (!$DryRun) {
                    cmd /c "assoc $type=ChromeHTML" | Out-Null
                    Write-Success "Set Chrome as default for $type files"
                } else {
                    Write-WouldPerform "Set Chrome as default for $type files"
                }
            } catch {
                Write-Warning "Could not set Chrome as default for $type files"
            }
        }
        
        # Get correct Chrome path
        $chromePath = ""
        if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe") {
            $chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
        } else {
            $chromePath = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        }
        
        # Launch Chrome to help user set it as default
        if (!$DryRun) {
            Write-Info "Opening Chrome to help you set it as your default browser"
            Start-Process $chromePath -ArgumentList "--new-window chrome://settings/defaultBrowser"
        } else {
            Write-WouldPerform "Open Chrome default browser settings page"
        }
        
        # Clear instructions for user
        Write-Warning "Windows 10 restricts programmatic browser default changes"
        Write-Info "To set Chrome as default: Settings > Apps > Default Apps > Web Browser > Chrome"
        Write-Info "Or follow the prompt in Chrome to make it your default browser"
    } catch {
        Write-Warning "Setting Chrome as default browser failed: $_"
    }
}

function Set-FirefoxDefault {
    Write-Status "Setting Firefox as default browser..."
    
    try {
        # Prepare Firefox registry entries
        $progId = "FirefoxHTML"
        
        # Set default protocol handlers for HTTP/HTTPS
        $protoPath = "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations"
        $protocols = @("http", "https")
        
        foreach ($protocol in $protocols) {
            $protocolPath = "$protoPath\$protocol\UserChoice"
            
            # We can try but Windows often reverts these
            if (!(Test-Path $protocolPath)) {
                if (!$DryRun) {
                    New-Item -Path $protocolPath -Force | Out-Null
                } else {
                    Write-WouldPerform "Create registry path $protocolPath"
                }
            }
            
            try {
                if (!$DryRun) {
                    Set-ItemProperty -Path $protocolPath -Name "ProgId" -Value $progId -Type String -Force
                    Write-Success "Set Firefox as default for $protocol (may require user confirmation)"
                } else {
                    Write-WouldPerform "Set Firefox as default for $protocol protocol"
                }
            } catch {
                # Windows 10 actively prevents programmatic changes here
                Write-Warning "Could not set Firefox as default for $protocol protocol"
            }
        }
        
        # Set default file associations
        $fileTypes = @(".htm", ".html")
        foreach ($type in $fileTypes) {
            try {
                if (!$DryRun) {
                    cmd /c "assoc $type=FirefoxHTML" | Out-Null
                    Write-Success "Set Firefox as default for $type files"
                } else {
                    Write-WouldPerform "Set Firefox as default for $type files"
                }
            } catch {
                Write-Warning "Could not set Firefox as default for $type files"
            }
        }
        
        # Launch Firefox to help user set it as default
        if (!$DryRun) {
            Write-Info "Opening Firefox to help you set it as your default browser"
            Start-Process "C:\Program Files\Mozilla Firefox\firefox.exe" -ArgumentList "-new-tab about:preferences#general"
        } else {
            Write-WouldPerform "Open Firefox preferences page"
        }
        
        # Clear instructions for user
        Write-Warning "Windows 10 restricts programmatic browser default changes"
        Write-Info "To set Firefox as default: Settings > Apps > Default Apps > Web Browser > Firefox"
        Write-Info "Or follow the prompt in Firefox to make it your default browser"
    } catch {
        Write-Warning "Setting Firefox as default browser failed: $_"
    }
}#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 10 Debloat Script - Disables unwanted features and services
.DESCRIPTION
    This script disables telemetry, Cortana, OneDrive, web search in taskbar,
    and limits Microsoft Edge. Designed to be idempotent (safely re-runnable).
.PARAMETER Telemetry
    Disable Windows telemetry/data collection
.PARAMETER Cortana
    Disable Cortana and related features
.PARAMETER OneDrive
    Remove OneDrive and prevent reinstallation
.PARAMETER WebSearch
    Disable web search in taskbar
.PARAMETER Edge
    Contain Microsoft Edge browser
.PARAMETER Firefox
    Install Firefox and attempt to set as default
.PARAMETER All
    Run all operations (default if no parameters specified)
.EXAMPLE
    .\windows-debloat.ps1 -Telemetry -Firefox
    # Only runs telemetry disabling and Firefox installation
.EXAMPLE
    .\windows-debloat.ps1
    # Runs all operations (equivalent to -All)
.NOTES
    Run with administrator privileges
#>
param (
    [switch]$Telemetry,
    [switch]$Cortana,
    [switch]$OneDrive,
    [switch]$WebSearch,
    [switch]$Edge,
    [switch]$Firefox,
    [switch]$Chrome,
    [switch]$All
)

# Message stacks for different severity levels
$global:messageTypes = @{
    "Critical" = @() # For failures requiring action
    "Warning"  = @() # For limitations requiring manual steps
    "Info"     = @() # For context/follow-up instructions
}

$global:actionsPerformed = @()
$global:wouldPerform = @() # Actions that would be performed in dry-run mode

# Status functions
function Write-Status($message) {
    Write-Host "$message" -ForegroundColor Cyan
}

function Write-Success($message) {
    Write-Host "$message" -ForegroundColor Green
    $global:actionsPerformed += $message
}

function Write-WouldPerform($message) {
    Write-Host "WOULD PERFORM: $message" -ForegroundColor Magenta
    $global:wouldPerform += $message
}

function Write-Skip($message) {
    Write-Host "SKIPPED: $message" -ForegroundColor DarkGray
}

function Write-Critical($message) {
    Write-Host "CRITICAL: $message" -ForegroundColor Red -BackgroundColor Black
    $global:messageTypes["Critical"] += $message
}

function Write-Warning($message) {
    Write-Host "WARNING: $message" -ForegroundColor Yellow
    $global:messageTypes["Warning"] += $message
}

function Write-Info($message) {
    Write-Host "INFO: $message" -ForegroundColor White
    $global:messageTypes["Info"] += $message
}

function Process-Messages {
    # Process critical errors
    if ($global:messageTypes["Critical"].Count -gt 0) { 
        Write-Host "`n⚠️ Critical errors requiring attention:" -ForegroundColor Red
        
        foreach ($message in $global:messageTypes["Critical"]) {
            # Pattern match specific errors for custom handling
            if ($message -match "Firefox") {
                Write-Host "- Browser setup failed: $message" -ForegroundColor Red
            } elseif ($message -match "Chrome") {
                Write-Host "- Browser setup failed: $message" -ForegroundColor Red
            } elseif ($message -match "Telemetry") {
                Write-Host "- Telemetry blocking incomplete: $message" -ForegroundColor Red
            } elseif ($message -match "Cortana") {
                Write-Host "- Cortana disabling failed: $message" -ForegroundColor Red
            } elseif ($message -match "OneDrive") {
                Write-Host "- OneDrive removal incomplete: $message" -ForegroundColor Red
            } elseif ($message -match "Edge") {
                Write-Host "- Edge containment incomplete: $message" -ForegroundColor Red
            } else {
                Write-Host "- $message" -ForegroundColor Red
            }
        }
    }
    
    # Process warnings that require manual steps
    if ($global:messageTypes["Warning"].Count -gt 0) {
        Write-Host "`nWarnings - Manual steps required:" -ForegroundColor Yellow
        foreach ($message in $global:messageTypes["Warning"]) {
            Write-Host "- $message" -ForegroundColor Yellow
        }
    }
    
    # Process informational messages
    if ($global:messageTypes["Info"].Count -gt 0) {
        Write-Host "`nInformation and next steps:" -ForegroundColor White
        foreach ($message in $global:messageTypes["Info"]) {
            Write-Host "- $message" -ForegroundColor White
        }
    }
}

function Process-Summary {
    if ($DryRun) {
        if ($global:wouldPerform.Count -eq 0) {
            Write-Host "`nNo changes would be made - system already configured." -ForegroundColor Yellow
        } else {
            Write-Host "`nActions that would be performed:" -ForegroundColor Magenta
            foreach ($action in $global:wouldPerform) {
                Write-Host "- $action" -ForegroundColor Magenta
            }
            
            # Generate the command to run with -Apply
            $params = [System.Collections.ArrayList]@()
            if ($Telemetry) { $params.Add("-Telemetry") | Out-Null }
            if ($Cortana) { $params.Add("-Cortana") | Out-Null }
            if ($OneDrive) { $params.Add("-OneDrive") | Out-Null }
            if ($WebSearch) { $params.Add("-WebSearch") | Out-Null }
            if ($Edge) { $params.Add("-Edge") | Out-Null }
            if ($Firefox) { $params.Add("-Firefox") | Out-Null }
            if ($Chrome) { $params.Add("-Chrome") | Out-Null }
            if ($All -or $params.Count -eq 0) { $params.Add("-All") | Out-Null }
            $params.Add("-Apply") | Out-Null
            
            $command = ".\$($MyInvocation.ScriptName) " + ($params -join " ")
            Write-Host "`nTo apply these changes, run:" -ForegroundColor White
            Write-Host $command -ForegroundColor Cyan
        }
    } else {
        if ($global:actionsPerformed.Count -eq 0) {
            Write-Host "`nNo changes were made - system already configured." -ForegroundColor Yellow
        } else {
            Write-Host "`nActions performed:" -ForegroundColor Green
            foreach ($action in $global:actionsPerformed) {
                Write-Host "- $action" -ForegroundColor Green
            }
        }
    }
}

#region Check Admin Rights
function Verify-AdminRights {
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Critical "This script must be run as Administrator!"
        return $false
    }
    return $true
}
#endregion

#region Browser Installation
function Install-Browser {
    param (
        [Parameter(Mandatory=$false)]
        [string]$BrowserChoice = ""
    )
    
    # Check for existing browser installations
    $chromeExists = Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -Or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    $firefoxExists = Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe"
    
    # Check current default browser
    $defaultBrowser = Get-DefaultBrowser
    
    # If both browsers exist and one is default, don't change anything unless explicitly requested
    if ($chromeExists -and $firefoxExists -and $defaultBrowser -ne "") {
        if ($BrowserChoice -eq "") {
            Write-Info "Found both Chrome and Firefox with '$defaultBrowser' as default"
            Write-Warning "Default browser not changed. Use -Chrome or -Firefox parameter to change default"
            return @{
                Success = $true
                Browser = $defaultBrowser
                Action = "None" # No action taken
            }
        }
    }
    
    # If a specific browser was explicitly requested
    if ($BrowserChoice -eq "Chrome") {
        $result = Install-Chrome
        $result.Action = "Installed" # Mark as installed or attempted
        return $result
    } elseif ($BrowserChoice -eq "Firefox") {
        $result = Install-Firefox
        $result.Action = "Installed" # Mark as installed or attempted
        return $result
    }
    
    # If only one browser exists, use it
    if ($chromeExists -and !$firefoxExists) {
        Write-Skip "Chrome already installed, using as default browser"
        return @{
            Success = $true
            Browser = "Chrome"
            Action = "Existing" # Using existing install
        }
    } elseif ($firefoxExists -and !$chromeExists) {
        Write-Skip "Firefox already installed, using as default browser"
        return @{
            Success = $true
            Browser = "Firefox"
            Action = "Existing" # Using existing install
        }
    } elseif ($chromeExists -and $firefoxExists) {
        # Both exist, but no explicit choice and no default set
        Write-Skip "Both Chrome and Firefox exist, defaulting to Firefox"
        return @{
            Success = $true
            Browser = "Firefox"
            Action = "Existing" # Using existing install
        }
    }
    
    # No browser found, install Firefox (as requested)
    $firefoxResult = Install-Firefox
    if ($firefoxResult.Success) {
        $firefoxResult.Action = "Installed"
        return $firefoxResult
    }
    
    # Firefox failed, try Chrome as fallback
    $chromeResult = Install-Chrome
    if ($chromeResult.Success) {
        $chromeResult.Action = "Installed"
        return $chromeResult
    }
    
    # Both failed
    Write-Critical "Failed to install any browser"
    return @{
        Success = $false
        Browser = ""
        Action = "Failed"
    }
}

function Get-DefaultBrowser {
    # Check default browser from registry
    $defaultBrowser = ""
    try {
        $httpHandler = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" -Name "ProgId" -ErrorAction SilentlyContinue
        if ($httpHandler) {
            if ($httpHandler.ProgId -like "*Chrome*") {
                $defaultBrowser = "Chrome"
            } elseif ($httpHandler.ProgId -like "*Firefox*") {
                $defaultBrowser = "Firefox"
            }
        }
    } catch {
        # Registry key not readable, default not determinable
        $defaultBrowser = ""
    }
    
    return $defaultBrowser
}

function Install-Chrome {
    Write-Status "Checking Chrome installation..."
    
    if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -Or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {
        Write-Skip "Chrome already installed"
        return @{
            Success = $true
            Browser = "Chrome"
        }
    }
    
    try {
        $downloadUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
        $installerPath = "$env:TEMP\chrome_installer.exe"
        
        Write-Status "Downloading Chrome installer..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
        
        Write-Status "Installing Chrome silently..."
        if (!$DryRun) {
            Start-Process -FilePath $installerPath -Args "/silent /install" -Wait
            
            # Verify installation
            if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -Or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {
                Write-Success "Chrome successfully installed"
                return @{
                    Success = $true
                    Browser = "Chrome"
                }
            } else {
                Write-Critical "Chrome installation failed - executable not found"
                return @{
                    Success = $false
                    Browser = "Chrome"
                }
            }
        } else {
            Write-WouldPerform "Install Chrome browser"
            return @{
                Success = $true
                Browser = "Chrome"
            }
        }
    } catch {
        Write-Critical "Chrome installation failed: $_"
        return @{
            Success = $false
            Browser = "Chrome"
        }
    } finally {
        # Clean up
        if (Test-Path $installerPath) {
            Remove-Item $installerPath -Force
        }
    }
}

function Install-Firefox {
    Write-Status "Checking Firefox installation..."
    
    if (Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe") {
        Write-Skip "Firefox already installed"
        return @{
            Success = $true
            Browser = "Firefox"
        }
    }
    
    try {
        $downloadUrl = "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US"
        $installerPath = "$env:TEMP\firefox_installer.exe"
        
        Write-Status "Downloading Firefox installer..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
        
        Write-Status "Installing Firefox silently..."
        if (!$DryRun) {
            Start-Process -FilePath $installerPath -Args "/S" -Wait
            
            # Verify installation
            if (Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe") {
                Write-Success "Firefox successfully installed"
                return @{
                    Success = $true
                    Browser = "Firefox"
                }
            } else {
                Write-Critical "Firefox installation failed - executable not found"
                return @{
                    Success = $false
                    Browser = "Firefox"
                }
            }
        } else {
            Write-WouldPerform "Install Firefox browser"
            return @{
                Success = $true
                Browser = "Firefox"
            }
        }
    } catch {
        Write-Critical "Firefox installation failed: $_"
        return @{
            Success = $false
            Browser = "Firefox"
        }
    } finally {
        # Clean up
        if (Test-Path $installerPath) {
            Remove-Item $installerPath -Force
        }
    }
}
#endregion

#region Disable Telemetry
function Disable-Telemetry {
    Write-Status "Disabling Windows telemetry/data collection..."

    try {
        # DiagTrack service
        $diagTrack = Get-Service -Name DiagTrack -ErrorAction SilentlyContinue
        if ($diagTrack -and $diagTrack.Status -eq "Running") {
            if (!$DryRun) {
                Stop-Service -Name DiagTrack -Force
                Set-Service -Name DiagTrack -StartupType Disabled
                Write-Success "Disabled DiagTrack (Connected User Experiences and Telemetry) service"
            } else {
                Write-WouldPerform "Disable DiagTrack (Connected User Experiences and Telemetry) service"
            }
        } else {
            Write-Skip "DiagTrack service already disabled"
        }
        
        # dmwappushsvc service
        $dmwappushsvc = Get-Service -Name dmwappushsvc -ErrorAction SilentlyContinue
        if ($dmwappushsvc -and $dmwappushsvc.Status -eq "Running") {
            if (!$DryRun) {
                Stop-Service -Name dmwappushsvc -Force
                Set-Service -Name dmwappushsvc -StartupType Disabled
                Write-Success "Disabled dmwappushsvc (WAP Push Message Routing) service"
            } else {
                Write-WouldPerform "Disable dmwappushsvc (WAP Push Message Routing) service"
            }
        } else {
            Write-Skip "dmwappushsvc service already disabled or not found"
        }

        # Telemetry via Registry
        $telemetryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (!(Test-Path $telemetryPath)) {
            if (!$DryRun) {
                New-Item -Path $telemetryPath -Force | Out-Null
            } else {
                Write-WouldPerform "Create registry path $telemetryPath"
            }
        }
        
        # AllowTelemetry (0 = Off)
        $allowTelemetry = Get-ItemProperty -Path $telemetryPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue
        if (!$allowTelemetry -or $allowTelemetry.AllowTelemetry -ne 0) {
            if (!$DryRun) {
                Set-ItemProperty -Path $telemetryPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force
                Write-Success "Set telemetry AllowTelemetry to 0 (Off)"
            } else {
                Write-WouldPerform "Set telemetry AllowTelemetry to 0 (Off)"
            }
        } else {
            Write-Skip "Telemetry AllowTelemetry already set to 0"
        }
        
        # Disable Customer Experience Improvement Program
        $ceipPath = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
        if (!(Test-Path $ceipPath)) {
            if (!$DryRun) {
                New-Item -Path $ceipPath -Force | Out-Null
            } else {
                Write-WouldPerform "Create registry path $ceipPath"
            }
        }
        
        $ceipEnabled = Get-ItemProperty -Path $ceipPath -Name "CEIPEnable" -ErrorAction SilentlyContinue
        if (!$ceipEnabled -or $ceipEnabled.CEIPEnable -ne 0) {
            if (!$DryRun) {
                Set-ItemProperty -Path $ceipPath -Name "CEIPEnable" -Value 0 -Type DWord -Force
                Write-Success "Disabled Customer Experience Improvement Program"
            } else {
                Write-WouldPerform "Disable Customer Experience Improvement Program"
            }
        } else {
            Write-Skip "Customer Experience Improvement Program already disabled"
        }
        
        # Block telemetry domains in hosts file
        $hostsPath = "$env:windir\System32\drivers\etc\hosts"
        $hosts = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue
        $telemetryDomains = @(
            "vortex.data.microsoft.com",
            "vortex-win.data.microsoft.com",
            "telecommand.telemetry.microsoft.com",
            "telecommand.telemetry.microsoft.com.nsatc.net",
            "oca.telemetry.microsoft.com",
            "oca.telemetry.microsoft.com.nsatc.net",
            "sqm.telemetry.microsoft.com",
            "sqm.telemetry.microsoft.com.nsatc.net",
            "watson.telemetry.microsoft.com",
            "watson.telemetry.microsoft.com.nsatc.net",
            "redir.metaservices.microsoft.com",
            "choice.microsoft.com",
            "choice.microsoft.com.nsatc.net",
            "df.telemetry.microsoft.com",
            "reports.wes.df.telemetry.microsoft.com",
            "services.wes.df.telemetry.microsoft.com",
            "sqm.df.telemetry.microsoft.com",
            "telemetry.microsoft.com",
            "watson.ppe.telemetry.microsoft.com",
            "telemetry.appex.bing.net",
            "telemetry.urs.microsoft.com",
            "telemetry.appex.bing.net:443",
            "settings-sandbox.data.microsoft.com",
            "vortex-sandbox.data.microsoft.com",
            "survey.watson.microsoft.com",
            "watson.live.com",
            "watson.microsoft.com",
            "statsfe2.ws.microsoft.com",
            "corpext.msitadfs.glbdns2.microsoft.com",
            "compatexchange.cloudapp.net",
            "cs1.wpc.v0cdn.net",
            "a-0001.a-msedge.net",
            "statsfe2.update.microsoft.com.akadns.net",
            "sls.update.microsoft.com.akadns.net",
            "fe2.update.microsoft.com.akadns.net",
            "diagnostics.support.microsoft.com",
            "corp.sts.microsoft.com",
            "statsfe1.ws.microsoft.com",
            "pre.footprintpredict.com",
            "i1.services.social.microsoft.com",
            "i1.services.social.microsoft.com.nsatc.net",
            "feedback.windows.com",
            "feedback.microsoft-hohm.com",
            "feedback.search.microsoft.com"
        )
        
        $domainsAdded = $false
        foreach ($domain in $telemetryDomains) {
            $pattern = "^\s*127\.0\.0\.1\s+$([regex]::Escape($domain))\s*$"
            if ($hosts -notmatch $pattern) {
                if (!$DryRun) {
                    Add-Content -Path $hostsPath -Value "127.0.0.1 $domain" -Force
                    $domainsAdded = $true
                } else {
                    Write-WouldPerform "Add telemetry domain $domain to hosts file"
                }
            }
        }
        
        if ($domainsAdded -and !$DryRun) {
            Write-Success "Added telemetry domains to hosts file"
        } elseif (!$domainsAdded) {
            Write-Skip "Telemetry domains already in hosts file"
        }
        
        # Disable scheduled tasks
        $telemetryTasks = @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Autochk\Proxy",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            "\Microsoft\Windows\Feedback\Siuf\DmClient",
            "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
        )
        
        $tasksDisabled = $false
        foreach ($task in $telemetryTasks) {
            $taskObj = Get-ScheduledTask -TaskPath $task -ErrorAction SilentlyContinue
            if ($taskObj -and $taskObj.State -ne "Disabled") {
                if (!$DryRun) {
                    Disable-ScheduledTask -TaskPath $task -ErrorAction SilentlyContinue | Out-Null
                    $tasksDisabled = $true
                } else {
                    Write-WouldPerform "Disable scheduled task $task"
                    $tasksDisabled = $true
                }
            }
        }
        
        if ($tasksDisabled -and !$DryRun) {
            Write-Success "Disabled telemetry scheduled tasks"
        } elseif (!$tasksDisabled) {
            Write-Skip "Telemetry scheduled tasks already disabled"
        }
        
        Write-Info "Telemetry may still be partially active after Windows updates - re-run script if needed"
    } catch {
        Write-Critical "Telemetry disabling failed: $_"
    }
}
#endregion

#region Disable Cortana
function Disable-Cortana {
    Write-Status "Disabling Cortana..."
    
    try {
        # Cortana registry settings
        $cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        if (!(Test-Path $cortanaPath)) {
            if (!$DryRun) {
                New-Item -Path $cortanaPath -Force | Out-Null
            } else {
                Write-WouldPerform "Create registry path $cortanaPath"
            }
        }
        
        # Disable Cortana
        $allowCortana = Get-ItemProperty -Path $cortanaPath -Name "AllowCortana" -ErrorAction SilentlyContinue
        if (!$allowCortana -or $allowCortana.AllowCortana -ne 0) {
            if (!$DryRun) {
                Set-ItemProperty -Path $cortanaPath -Name "AllowCortana" -Value 0 -Type DWord -Force
                Write-Success "Disabled Cortana"
            } else {
                Write-WouldPerform "Disable Cortana"
            }
        } else {
            Write-Skip "Cortana already disabled"
        }
        
        # Disable Cortana in search
        $cortanaConsent = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -ErrorAction SilentlyContinue
        if (!$cortanaConsent -or $cortanaConsent.CortanaConsent -ne 0) {
            if (!$DryRun) {
                Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWord -Force
                Write-Success "Disabled Cortana in search"
            } else {
                Write-WouldPerform "Disable Cortana in search"
            }
        } else {
            Write-Skip "Cortana in search already disabled"
        }
        
        # Disable web search
        $webSearch = Get-ItemProperty -Path $cortanaPath -Name "DisableWebSearch" -ErrorAction SilentlyContinue
        if (!$webSearch -or $webSearch.DisableWebSearch -ne 1) {
            if (!$DryRun) {
                Set-ItemProperty -Path $cortanaPath -Name "DisableWebSearch" -Value 1 -Type DWord -Force
                Write-Success "Disabled web search"
            } else {
                Write-WouldPerform "Disable web search"
            }
        } else {
            Write-Skip "Web search already disabled"
        }
        
        # Disable Bing in Windows Search
        $bingSearch = Get-ItemProperty -Path $cortanaPath -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
        if (!$bingSearch -or $bingSearch.BingSearchEnabled -ne 0) {
            if (!$DryRun) {
                Set-ItemProperty -Path $cortanaPath -Name "BingSearchEnabled" -Value 0 -Type DWord -Force
                Write-Success "Disabled Bing in Windows Search"
            } else {
                Write-WouldPerform "Disable Bing in Windows Search"
            }
        } else {
            Write-Skip "Bing in Windows Search already disabled"
        }
        
        Write-Info "Cortana may reactivate after major Windows updates"
    } catch {
        Write-Critical "Cortana disabling failed: $_"
    }
}
#endregion

#region Remove OneDrive
function Remove-OneDrive {
    Write-Status "Removing OneDrive..."
    
    try {
        # Stop OneDrive process
        if (!$DryRun) {
            Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force
        } else {
            Write-WouldPerform "Stop OneDrive process"
        }
        
        # Uninstall OneDrive
        $oneDriveUninstall = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
        if (!(Test-Path $oneDriveUninstall)) {
            $oneDriveUninstall = "$env:SystemRoot\System32\OneDriveSetup.exe"
        }
        
        if (Test-Path $oneDriveUninstall) {
            if (!$DryRun) {
                Start-Process $oneDriveUninstall -ArgumentList "/uninstall" -Wait
                Write-Success "Uninstalled OneDrive"
            } else {
                Write-WouldPerform "Uninstall OneDrive"
            }
        } else {
            Write-Skip "OneDrive uninstaller not found"
        }
        
        # Remove OneDrive from Explorer
        $explorerPath = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        if (Test-Path $explorerPath) {
            if (!$DryRun) {
                Set-ItemProperty -Path $explorerPath -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -Force
                Write-Success "Removed OneDrive from Explorer"
            } else {
                Write-WouldPerform "Remove OneDrive from Explorer"
            }
        } else {
            Write-Skip "OneDrive Explorer entry not found"
        }
        
        # Remove 64-bit OneDrive from Explorer
        $explorer64Path = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        if (Test-Path $explorer64Path) {
            if (!$DryRun) {
                Set-ItemProperty -Path $explorer64Path -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -Force
                Write-Success "Removed 64-bit OneDrive from Explorer"
            } else {
                Write-WouldPerform "Remove 64-bit OneDrive from Explorer"
            }
        } else {
            Write-Skip "OneDrive 64-bit Explorer entry not found"
        }
        
        # Prevent OneDrive reinstallation
        $preventPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        if (!(Test-Path $preventPath)) {
            if (!$DryRun) {
                New-Item -Path $preventPath -Force | Out-Null
            } else {
                Write-WouldPerform "Create registry path $preventPath"
            }
        }
        
        $disableFileSyncNGSC = Get-ItemProperty -Path $preventPath -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
        if (!$disableFileSyncNGSC -or $disableFileSyncNGSC.DisableFileSyncNGSC -ne 1) {
            if (!$DryRun) {
                Set-ItemProperty -Path $preventPath -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
                Write-Success "Prevented OneDrive reinstallation"
            } else {
                Write-WouldPerform "Prevent OneDrive reinstallation"
            }
        } else {
            Write-Skip "OneDrive reinstallation already prevented"
        }
        
        Write-Info "OneDrive may attempt to reinstall during Windows updates"
    } catch {
        Write-Critical "OneDrive removal failed: $_"
    }
}
#endregion

#region Disable Web Search in Taskbar
function Disable-WebSearch {
    Write-Status "Disabling web search in taskbar..."
    
    try {
        # Disable web search in start menu
        $searchPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
        if (!(Test-Path $searchPath)) {
            if (!$DryRun) {
                New-Item -Path $searchPath -Force | Out-Null
            } else {
                Write-WouldPerform "Create registry path $searchPath"
            }
        }
        
        $searchboxTaskbar = Get-ItemProperty -Path $searchPath -Name "SearchboxTaskbarMode" -ErrorAction SilentlyContinue
        if (!$searchboxTaskbar -or $searchboxTaskbar.SearchboxTaskbarMode -ne 1) {
            if (!$DryRun) {
                Set-ItemProperty -Path $searchPath -Name "SearchboxTaskbarMode" -Value 1 -Type DWord -Force
                Write-Success "Set search box to icon-only mode"
            } else {
                Write-WouldPerform "Set search box to icon-only mode"
            }
        } else {
            Write-Skip "Search box already in icon-only mode"
        }
        
        $deviceHistorySearch = Get-ItemProperty -Path $searchPath -Name "DeviceHistoryEnabled" -ErrorAction SilentlyContinue
        if (!$deviceHistorySearch -or $deviceHistorySearch.DeviceHistoryEnabled -ne 0) {
            if (!$DryRun) {
                Set-ItemProperty -Path $searchPath -Name "DeviceHistoryEnabled" -Value 0 -Type DWord -Force
                Write-Success "Disabled device history search"
            } else {
                Write-WouldPerform "Disable device history search"
            }
        } else {
            Write-Skip "Device history search already disabled"
        }
        
        $disableSearch = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableSearch" -ErrorAction SilentlyContinue
        if (!$disableSearch -or $disableSearch.DisableSearch -ne 1) {
            if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
                if (!$DryRun) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
                } else {
                    Write-WouldPerform "Create registry path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
                }
            }
            
            if (!$DryRun) {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableSearch" -Value 1 -Type DWord -Force
                Write-Success "Disabled web search"
            } else {
                Write-WouldPerform "Disable web search"
            }
        } else {
            Write-Skip "Web search already disabled"
        }
    } catch {
        Write-Critical "Web search disabling failed: $_"
    }
}
#endregion

#region Contain Edge
function Contain-Edge {
    Write-Status "Containing Microsoft Edge..."
    
    try {
        # Disable Edge first run experience
        $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        if (!(Test-Path $edgePath)) {
            if (!$DryRun) {
                New-Item -Path $edgePath -Force | Out-Null
            } else {
                Write-WouldPerform "Create registry path $edgePath"
            }
        }
        
        $firstRun = Get-ItemProperty -Path $edgePath -Name "HideFirstRunExperience" -ErrorAction SilentlyContinue
        if (!$firstRun -or $firstRun.HideFirstRunExperience -ne 1) {
            if (!$DryRun) {
                Set-ItemProperty -Path $edgePath -Name "HideFirstRunExperience" -Value 1 -Type DWord -Force
                Write-Success "Disabled Edge first run experience"
            } else {
                Write-WouldPerform "Disable Edge first run experience"
            }
        } else {
            Write-Skip "Edge first run experience already disabled"
        }
        
        # Disable Edge desktop shortcut creation
        $shortcutPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        $disableEdgeShortcut = Get-ItemProperty -Path $shortcutPath -Name "DisableEdgeDesktopShortcutCreation" -ErrorAction SilentlyContinue
        if (!$disableEdgeShortcut -or $disableEdgeShortcut.DisableEdgeDesktopShortcutCreation -ne 1) {
            if (!$DryRun) {
                Set-ItemProperty -Path $shortcutPath -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Type DWord -Force
                Write-Success "Disabled Edge desktop shortcut creation"
            } else {
                Write-WouldPerform "Disable Edge desktop shortcut creation"
            }
        } else {
            Write-Skip "Edge desktop shortcut creation already disabled"
        }
        
        # Remove Edge shortcuts
        $edgeShortcuts = @(
            "$env:USERPROFILE\Desktop\Microsoft Edge.lnk",
            "$env:PUBLIC\Desktop\Microsoft Edge.lnk"
        )
        
        $shortcutsRemoved = $false
        foreach ($shortcut in $edgeShortcuts) {
            if (Test-Path $shortcut) {
                if (!$DryRun) {
                    Remove-Item $shortcut -Force
                    $shortcutsRemoved = $true
                } else {
                    Write-WouldPerform "Remove Edge shortcut: $shortcut"
                    $shortcutsRemoved = $true
                }
            }
        }
        
        if ($shortcutsRemoved -and !$DryRun) {
            Write-Success "Removed Edge shortcuts"
        } elseif (!$shortcutsRemoved) {
            Write-Skip "No Edge shortcuts found to remove"
        }
        
        # Disable automatic browser choice
        $browserChoice = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        if (!(Test-Path $browserChoice)) {
            if (!$DryRun) {
                New-Item -Path $browserChoice -Force | Out-Null
            } else {
                Write-WouldPerform "Create registry path $browserChoice"
            }
        }
        
        $noBrowserChoice = Get-ItemProperty -Path $browserChoice -Name "NoNewAppAlert" -ErrorAction SilentlyContinue
        if (!$noBrowserChoice -or $noBrowserChoice.NoNewAppAlert -ne 1) {
            if (!$DryRun) {
                Set-ItemProperty -Path $browserChoice -Name "NoNewAppAlert" -Value 1 -Type DWord -Force
                Write-Success "Disabled automatic browser choice dialogs"
            } else {
                Write-WouldPerform "Disable automatic browser choice dialogs"
            }
        } else {
            Write-Skip "Automatic browser choice dialogs already disabled"
        }
        
        Write-Warning "Edge cannot be completely removed without risking system instability"
        Write-Info "Some Edge components remain active for core Windows functionality"
    } catch {
        Write-Critical "Edge containment failed: $_"
    }
}Null
            } else {
                Write-WouldPerform "Create registry path $edgePath"
            }
        }
        
        $firstRun = Get-ItemProperty -Path $edgePath -Name "HideFirstRunExperience" -ErrorAction SilentlyContinue
        if (!$firstRun -or $firstRun.HideFirstRunExperience -ne 1) {
            if (!$DryRun) {
                Set-ItemProperty -Path $edgePath -Name "HideFirstRunExperience" -Value 1 -Type DWord -Force
                Write-Success "Disabled Edge first run experience"
            } else {
                Write-WouldPerform "Disable Edge first run experience"
            }
        } else {
            Write-Skip "Edge first run experience already disabled"
        }
        
        # Disable Edge desktop shortcut creation
        $shortcutPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        $disableEdgeShortcut = Get-ItemProperty -Path $shortcutPath -Name "DisableEdgeDesktopShortcutCreation" -ErrorAction SilentlyContinue
        if (!$disableEdgeShortcut -or $disableEdgeShortcut.DisableEdgeDesktopShortcutCreation -ne 1) {
            if (!$DryRun) {
                Set-ItemProperty -Path $shortcutPath -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Type DWord -Force
                Write-Success "Disabled Edge desktop shortcut creation"
            } else {
                Write-WouldPerform "Disable Edge desktop shortcut creation"
            }
        } else {
            Write-Skip "Edge desktop shortcut creation already disabled"
        }
        
        # Remove Edge shortcuts
        $edgeShortcuts = @(
            "$env:USERPROFILE\Desktop\Microsoft Edge.lnk",
            "$env:PUBLIC\Desktop\Microsoft Edge.lnk"
        )
        
        $shortcutsRemoved = $false
        foreach ($shortcut in $edgeShortcuts) {
            if (Test-Path $shortcut) {
                if (!$DryRun) {
                    Remove-Item $shortcut -Force
                    $shortcutsRemoved = $true
                } else {
                    Write-WouldPerform "Remove Edge shortcut: $shortcut"
                    $shortcutsRemoved = $true
                }
            }
        }
        
        if ($shortcutsRemoved -and !$DryRun) {
            Write-Success "Removed Edge shortcuts"
        } elseif (!$shortcutsRemoved) {
            Write-Skip "No Edge shortcuts found to remove"
        }
        
        # Disable automatic browser choice
        $browserChoice = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        if (!(Test-Path $browserChoice)) {
            if (!$DryRun) {
                New-Item -Path $browserChoice -Force | Out-
#endregion

#region Set Browser as Default
function Set-BrowserDefault {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Browser = ""
    )
    
    # Check current default browser
    $currentDefault = Get-DefaultBrowser
    
    # Determine which browser to set as default
    if ($Browser -eq "Chrome") {
        if (!(Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -Or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")) {
            Write-Warning "Chrome not installed - cannot set as default browser"
            return
        }
        if ($currentDefault -eq "Chrome") {
            Write-Skip "Chrome is already set as default browser"
        } else {
            Set-ChromeDefault
        }
    } 
    elseif ($Browser -eq "Firefox") {
        if (!(Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe")) {
            Write-Warning "Firefox not installed - cannot set as default browser"
            return
        }
        if ($currentDefault -eq "Firefox") {
            Write-Skip "Firefox is already set as default browser"
        } else {
            Set-FirefoxDefault
        }
    }
    else {
        # Auto-detect installed browser
        if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -Or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {
            if ($currentDefault -eq "Chrome") {
                Write-Skip "Chrome is already set as default browser"
            } else {
                Set-ChromeDefault
            }
        }
        elseif (Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe") {
            if ($currentDefault -eq "Firefox") {
                Write-Skip "Firefox is already set as default browser"
            } else {
                Set-FirefoxDefault
            }
        }
        else {
            Write-Warning "No supported browser installed - cannot set default browser"
        }
    }
}

function Set-ChromeDefault {
    Write-Status "Setting Chrome as default browser..."
    
    try {
        # Prepare Chrome registry entries
        $progId = "ChromeHTML"
        
        # Set default protocol handlers for HTTP/HTTPS
        $protoPath = "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations"
        $protocols = @("http", "https")
        
        foreach ($protocol in $protocols) {
            $protocolPath = "$protoPath\$protocol\UserChoice"
            
            # We can try but Windows often reverts these
            if (!(Test-Path $protocolPath)) {
                New-Item -Path $protocolPath -Force | Out-Null
            }
            
            try {
                Set-ItemProperty -Path $protocolPath -Name "ProgId" -Value $progId -Type String -Force
                Write-Success "Set Chrome as default for $protocol (may require user confirmation)"
            } catch {
                # Windows 10 actively prevents programmatic changes here
                Write-Warning "Could not set Chrome as default for $protocol protocol"
            }
        }
        
        # Set default file associations
        $fileTypes = @(".htm", ".html")
        foreach ($type in $fileTypes) {
            try {
                cmd /c "assoc $type=ChromeHTML" | Out-Null
                Write-Success "Set Chrome as default for $type files"
            } catch {
                Write-Warning "Could not set Chrome as default for $type files"
            }
        }
        
        # Get correct Chrome path
        $chromePath = ""
        if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe") {
            $chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
        } else {
            $chromePath = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        }
        
        # Launch Chrome to help user set it as default
        Write-Info "Opening Chrome to help you set it as your default browser"
        Start-Process $chromePath -ArgumentList "--new-window chrome://settings/defaultBrowser"
        
        # Clear instructions for user
        Write-Warning "Windows 10 restricts programmatic browser default changes"
        Write-Info "To set Chrome as default: Settings > Apps > Default Apps > Web Browser > Chrome"
        Write-Info "Or follow the prompt in Chrome to make it your default browser"
    } catch {
        Write-Warning "Setting Chrome as default browser failed: $_"
    }
}

function Set-FirefoxDefault {
    Write-Status "Setting Firefox as default browser..."
    
    try {
        # Prepare Firefox registry entries
        $progId = "FirefoxHTML"
        
        # Set default protocol handlers for HTTP/HTTPS
        $protoPath = "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations"
        $protocols = @("http", "https")
        
        foreach ($protocol in $protocols) {
            $protocolPath = "$protoPath\$protocol\UserChoice"
            
            # We can try but Windows often reverts these
            if (!(Test-Path $protocolPath)) {
                New-Item -Path $protocolPath -Force | Out-Null
            }
            
            try {
                Set-ItemProperty -Path $protocolPath -Name "ProgId" -Value $progId -Type String -Force
                Write-Success "Set Firefox as default for $protocol (may require user confirmation)"
            } catch {
                # Windows 10 actively prevents programmatic changes here
                Write-Warning "Could not set Firefox as default for $protocol protocol"
            }
        }
        
        # Set default file associations
        $fileTypes = @(".htm", ".html")
        foreach ($type in $fileTypes) {
            try {
                cmd /c "assoc $type=FirefoxHTML" | Out-Null
                Write-Success "Set Firefox as default for $type files"
            } catch {
                Write-Warning "Could not set Firefox as default for $type files"
            }
        }
        
        # Launch Firefox to help user set it as default
        Write-Info "Opening Firefox to help you set it as your default browser"
        Start-Process "C:\Program Files\Mozilla Firefox\firefox.exe" -ArgumentList "-new-tab about:preferences#general"
        
        # Clear instructions for user
        Write-Warning "Windows 10 restricts programmatic browser default changes"
        Write-Info "To set Firefox as default: Settings > Apps > Default Apps > Web Browser > Firefox"
        Write-Info "Or follow the prompt in Firefox to make it your default browser"
    } catch {
        Write-Warning "Setting Firefox as default browser failed: $_"
    }
}
#endregion

#region Main Execution
function Main {
    Write-Host "===== Windows 10 Debloat Script =====" -ForegroundColor Green
    
    if ($DryRun) {
        Write-Host "RUNNING IN DRY-RUN MODE - No changes will be made" -ForegroundColor Magenta
        Write-Host "Use -Apply parameter to apply changes" -ForegroundColor Magenta
    } else {
        Write-Host "CHANGES WILL BE APPLIED" -ForegroundColor Green
    }
    
    # Check admin rights
    if (!(Verify-AdminRights)) {
        Process-Messages
        exit 1
    }
    
    # Determine which functions to run
    $runAll = $All -or (!$Telemetry -and !$Cortana -and !$OneDrive -and !$WebSearch -and !$Edge -and !$Firefox -and !$Chrome)
    
    if ($runAll) {
        Write-Host "Running all operations..." -ForegroundColor Green
        Disable-Telemetry
        Disable-Cortana
        Remove-OneDrive
        Disable-WebSearch
        Contain-Edge
        
        # Default behavior - auto-detect with preferences
        $browserResult = Install-Browser
        if ($browserResult.Success -and $browserResult.Action -ne "None") {
            Set-BrowserDefault -Browser $browserResult.Browser
        }
    } else {
        if ($Telemetry) { Disable-Telemetry }
        if ($Cortana) { Disable-Cortana }
        if ($OneDrive) { Remove-OneDrive }
        if ($WebSearch) { Disable-WebSearch }
        if ($Edge) { Contain-Edge }
        if ($Firefox) { 
            $browserResult = Install-Browser -BrowserChoice "Firefox"
            if ($browserResult.Success) { Set-BrowserDefault -Browser "Firefox" }
        }
        if ($Chrome) {
            $browserResult = Install-Browser -BrowserChoice "Chrome"
            if ($browserResult.Success) { Set-BrowserDefault -Browser "Chrome" }
        }
    }
    
    # Process errors, warnings, info and show summary
    Process-Messages
    Process-Summary
}

# Run the main function
Main
