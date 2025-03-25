#Requires -RunAsAdministrator
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
.PARAMETER Chrome
    Install Chrome and attempt to set as default
.PARAMETER All
    Run all operations (default if no parameters specified)
.PARAMETER DryRun
    Simulate operations without making changes (preview mode)
.PARAMETER Apply
    Apply changes (overrides DryRun)
.EXAMPLE
    .\windows-debloat.ps1 -Telemetry -Firefox
    # Only runs telemetry disabling and Firefox installation
.EXAMPLE
    .\windows-debloat.ps1 -DryRun
    # Simulates all operations without making changes
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
    [switch]$All,
    [switch]$DryRun,
    [switch]$Apply
)

# Configuration and global variables
$ALWAYS_APPLY = $false # set to true to use at your own risk
$global:DryRun = $DryRun -and !$Apply -and !$ALWAYS_APPLY
$global:messageTypes = @{
    "Critical" = @() # For failures requiring action
    "Warning"  = @() # For limitations requiring manual steps
    "Info"     = @() # For context/follow-up instructions
}
$global:actionsPerformed = @()
$global:wouldPerform = @() # Actions that would be performed in dry-run mode

#region Helper Functions
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
    if ($global:DryRun) {
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

function Verify-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-NOT $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Critical "This script must be run as Administrator!"
        return $false
    }
    return $true
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
#endregion

#region Browser Installation Functions
function Install-Chrome {
    Write-Status "Checking Chrome installation..."
    
    if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {
        Write-Skip "Chrome already installed"
        return @{
            Success = $true
            Browser = "Chrome"
        }
    }
    
    try {
        $downloadUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
        $installerPath = Join-Path $env:TEMP "chrome_installer.exe"
        
        Write-Status "Downloading Chrome installer..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing
        
        Write-Status "Installing Chrome silently..."
        if (!$global:DryRun) {
            Start-Process -FilePath $installerPath -Args "/silent /install" -Wait
            
            # Verify installation
            Start-Sleep -Seconds 2 # Give installer time to finish
            if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {
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
                    Error = "Chrome executable not found after installation"
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
            Error = "Exception: $_"
        }
    } finally {
        # Clean up
        if (Test-Path $installerPath) {
            Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
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
        $installerPath = Join-Path $env:TEMP "firefox_installer.exe"
        
        Write-Status "Downloading Firefox installer..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing
        
        Write-Status "Installing Firefox silently..."
        if (!$global:DryRun) {
            Start-Process -FilePath $installerPath -Args "/S" -Wait
            
            # Verify installation
            Start-Sleep -Seconds 2 # Give installer time to finish
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
                    Error = "Firefox executable not found after installation"
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
            Error = "Exception: $_"
        }
    } finally {
        # Clean up
        if (Test-Path $installerPath) {
            Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Install-Browser {
    param (
        [Parameter(Mandatory=$false)]
        [string]$BrowserChoice = ""
    )
    
    # Check for existing browser installations
    $chromeExists = Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
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
    
    # No browser found, install Firefox (as default)
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
        Error = "Both Firefox and Chrome installation attempts failed"
    }
}
#endregion

#region Browser Default Functions
function Set-ChromeDefault {
    Write-Status "Setting Chrome as default browser..."
    
    try {
        # Prepare Chrome registry entries
        $progId = "ChromeHTML"
        
        # Set default protocol handlers for HTTP/HTTPS
        $protoPath = "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations"
        $protocols = @("http", "https")
        
        foreach ($protocol in $protocols) {
            $protocolPath = Join-Path $protoPath "$protocol\UserChoice"
            
            # We can try but Windows often reverts these
            if (!(Test-Path $protocolPath)) {
                if (!$global:DryRun) {
                    New-Item -Path $protocolPath -Force | Out-Null
                } else {
                    Write-WouldPerform "Create registry path $protocolPath"
                }
            }
            
            try {
                if (!$global:DryRun) {
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
                if (!$global:DryRun) {
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
        if (!$global:DryRun) {
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
            $protocolPath = Join-Path $protoPath "$protocol\UserChoice"
            
            # We can try but Windows often reverts these
            if (!(Test-Path $protocolPath)) {
                if (!$global:DryRun) {
                    New-Item -Path $protocolPath -Force | Out-Null
                } else {
                    Write-WouldPerform "Create registry path $protocolPath"
                }
            }
            
            try {
                if (!$global:DryRun) {
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
                if (!$global:DryRun) {
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
        if (!$global:DryRun) {
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
}

function Set-BrowserDefault {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Browser = ""
    )
    
    # Check current default browser
    $currentDefault = Get-DefaultBrowser
    
    # Determine which browser to set as default
    if ($Browser -eq "Chrome") {
        if (!(Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")) {
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
        if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe" -or Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {
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
#endregion

#region Feature Manipulation Functions
function Disable-Telemetry {
    Write-Status "Disabling Windows telemetry/data collection..."

    try {
        # DiagTrack service
        $diagTrack = Get-Service -Name DiagTrack -ErrorAction SilentlyContinue
        if ($diagTrack -and $diagTrack.Status -eq "Running") {
            if (!$global:DryRun) {
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
            if (!$global:DryRun) {
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
            if (!$global:DryRun) {
                New-Item -Path $telemetryPath -Force | Out-Null
            } else {
                Write-WouldPerform "Create registry path $telemetryPath"
            }
        }
        
        # AllowTelemetry (0 = Off)
        $allowTelemetry = Get-ItemProperty -Path $telemetryPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue
        $currentValue = if ($allowTelemetry) { $allowTelemetry.AllowTelemetry } else { -1 }
        if ($currentValue -ne 0) {
            if (!$global:DryRun) {
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
            if (!$global:DryRun) {
                New-Item -Path $ceipPath -Force | Out-Null
            } else {
                Write-WouldPerform "Create registry path $ceipPath"
            }
        }
        
        $ceipEnabled = Get-ItemProperty -Path $ceipPath -Name "CEIPEnable" -ErrorAction SilentlyContinue
        $currentCeipValue = if ($ceipEnabled) { $ceipEnabled.CEIPEnable } else { -1 }
        if ($currentCeipValue -ne 0) {
            if (!$global:DryRun) {
                Set-ItemProperty -Path $ceipPath -Name "CEIPEnable" -Value 0 -Type DWord -Force
                Write-Success "Disabled Customer Experience Improvement Program"
            } else {
                Write-WouldPerform "Disable Customer Experience Improvement Program"
            }
        } else {
            Write-Skip "Customer Experience Improvement Program already disabled"
        }
        
        $hostsPath = Join-Path $env:windir "System32\drivers\etc\hosts"

        # Check if hosts file exists and is writable
        if (!(Test-Path $hostsPath)) {
            try {
                if (!$global:DryRun) {
                    New-Item -Path $hostsPath -ItemType File -Force -ErrorAction Stop | Out-Null
                    Write-Success "Created hosts file at $hostsPath"
                } else {
                    Write-WouldPerform "Create hosts file at $hostsPath"
                }
            } catch {
                Write-Warning "Cannot create hosts file: $_"
                Write-Warning "Telemetry domain blocking skipped"
                # Skip the rest of this section
                return
            }
        }

        # Test write permissions by attempting to get an exclusive lock
        $hasWriteAccess = $false
        try {
            [System.IO.File]::Open($hostsPath, 'Open', 'Write', 'None').Close()
            $hasWriteAccess = $true
        } catch {
            Write-Warning "No write access to hosts file"
            if (!$global:DryRun) {
                Write-Info "Consider running the script with full administrator privileges"
                # Skip the rest of this section
                return
            }
        }

        # Read the hosts file content
        $hostsContent = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue

        # Create lookup table of existing domains
        $existingEntries = @{}
        foreach ($line in $hostsContent) {
            if ($line -match "^\s*\d+\.\d+\.\d+\.\d+\s+([^\s#]+)") {
                $existingEntries[$matches[1]] = $line
            }
        }

        # Domains to add with diff view
        $domainsToAdd = @()
        Write-Status "Analyzing hosts file changes:"

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
        
        # Check each domain and track what we need to add
        foreach ($domain in $telemetryDomains) {
            if (!$existingEntries.ContainsKey($domain)) {
                $domainsToAdd += "127.0.0.1 $domain"
                
                # Show what would be added in dry run
                if ($global:DryRun) {
                    Write-Host "  + 127.0.0.1 $domain" -ForegroundColor Green
                }
            } else {
                # Show existing entry
                if ($global:DryRun) {
                    Write-Host "  = $($existingEntries[$domain]) (already exists)" -ForegroundColor DarkGray
                }
            }
        }

        # Summary of changes
        if ($domainsToAdd.Count -gt 0) {
            if (!$global:DryRun -and $hasWriteAccess) {
                try {
                    $domainsToAdd | Out-File -FilePath $hostsPath -Append -Encoding ascii -ErrorAction Stop
                    Write-Success "Added $($domainsToAdd.Count) telemetry domains to hosts file"
                } catch {
                    Write-Warning "Cannot modify hosts file: $_"
                    Write-Warning "Make sure you're running as administrator with full privileges"
                }
            } elseif ($global:DryRun) {
                Write-WouldPerform "Add $($domainsToAdd.Count) telemetry domains to hosts file"
            }
        } else {
            Write-Skip "Telemetry domains already blocked in hosts file"
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
            try {
                $taskPath = Split-Path $task -Parent
                $taskName = Split-Path $task -Leaf
                $taskObj = Get-ScheduledTask -TaskPath "$taskPath\" -TaskName $taskName -ErrorAction SilentlyContinue
                if ($taskObj -and $taskObj.State -ne "Disabled") {
                    if (!$global:DryRun) {
                        Disable-ScheduledTask -TaskPath "$taskPath\" -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
                        $tasksDisabled = $true
                    } else {
                        Write-WouldPerform "Disable scheduled task $task"
                        $tasksDisabled = $true
                    }
                }
            } catch {
                Write-Warning "Could not disable task $task`: $_"
            }
        }
        
        if ($tasksDisabled -and !$global:DryRun) {
            Write-Success "Disabled telemetry scheduled tasks"
        } elseif (!$tasksDisabled) {
            Write-Skip "Telemetry scheduled tasks already disabled"
        }
        
        Write-Info "Telemetry may still be partially active after Windows updates - re-run script if needed"
    } catch {
        Write-Critical "Telemetry disabling failed: $_"
    }
}

# Verify admin rights before proceeding
if (!(Verify-AdminRights)) {
    Process-Messages
    exit 1
}

# Run selected operations or all if none specified
Write-Host "Windows 10 Debloat Script" -ForegroundColor Cyan
Write-Host "------------------------" -ForegroundColor Cyan

if ($global:DryRun) {
    Write-Host "DRY RUN MODE - No changes will be made" -ForegroundColor Yellow
}

# Determine which operations to run
$runAll = $All -or (!$Telemetry -and !$Cortana -and !$OneDrive -and !$WebSearch -and !$Edge -and !$Firefox -and !$Chrome)

# Run operations based on parameters
if ($Telemetry -or $runAll) { Disable-Telemetry }
if ($Firefox) { 
    $result = Install-Browser -BrowserChoice "Firefox"
    if ($result.Success) { Set-BrowserDefault -Browser "Firefox" }
}
if ($Chrome) { 
    $result = Install-Browser -BrowserChoice "Chrome" 
    if ($result.Success) { Set-BrowserDefault -Browser "Chrome" }
}

# Display summary
Process-Messages
Process-Summary
