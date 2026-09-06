#Requires -Version 5.1

<#
.SYNOPSIS
    RedTide -- Attack simulation toolkit for Microsoft Defender for Endpoint.

.DESCRIPTION
    Automates the setup of MDE attack simulations on Azure VMs using Invoke-AzVMRunCommand.
    Supports 13 attack simulations across three capability areas:

    Next-Generation Protection (P1):
      - CloudProtection:      Cloud-delivered protection blocks a test file
      - Amsi:                 AMSI integration detects malicious scripts in memory
      - AntivirusValidation:  EICAR test file validates antivirus is active
      - BehaviorMonitoring:   Behavior monitoring triggers offline detection alert
      - Pua:                  Potentially unwanted application detection via browser
      - AppReputation:        SmartScreen app reputation blocks untrusted downloads
      - UrlReputation:        SmartScreen URL reputation blocks malicious sites

    Attack Surface Reduction (P1):
      - ControlledFolder:     Controlled folder access blocks ransomware simulation
      - AsrRules:             Attack surface reduction rules block common attack vectors
      - CfaTestTool:          CFA test tool validates controlled folder access policies
      - ExploitProtection:    Exploit protection settings applied to the VM
      - NetworkProtection:    Network protection blocks connections to dangerous domains

    Endpoint Detection and Response (P2):
      - EdrDetection:         EDR detection test triggers an alert in the portal

    Run interactively (menu-driven) or with parameters for automation.

.PARAMETER Scenario
    Simulation to deploy. Valid values: CloudProtection, ControlledFolder, EdrDetection,
    Amsi, AntivirusValidation, BehaviorMonitoring, ExploitProtection, NetworkProtection,
    AsrRules, CfaTestTool, Pua, AppReputation, UrlReputation, All, Cleanup.
    Use 'All' to deploy all 13 attack simulations in sequence.
    If omitted, an interactive menu is shown.

.PARAMETER ResourceGroup
    Azure resource group containing the target VM. Azure mode only.

.PARAMETER VMName
    Name of the Azure VM to deploy the simulation to. Azure mode only.

.PARAMETER SubscriptionId
    Azure subscription ID. If omitted, uses the current Az context. Azure mode only.

.PARAMETER Local
    Run simulations on the local host instead of a remote Azure VM. Skips
    all Az / VM / RBAC checks. Requires running PowerShell as Administrator
    on a 64-bit Windows host with Defender Antivirus active. Mutually
    exclusive with -ResourceGroup, -VMName, and -SubscriptionId.

.PARAMETER LogPath
    Path for the log file. Defaults to ./logs/redtide-<timestamp>.log

.EXAMPLE
    # Interactive mode (Azure)
    .\Start-RedTide.ps1

.EXAMPLE
    # Direct mode (Azure)
    .\Start-RedTide.ps1 -Scenario CloudProtection -ResourceGroup "mde-demo-rg" -VMName "demo-win11"

.EXAMPLE
    # Deploy all simulations at once (Azure)
    .\Start-RedTide.ps1 -Scenario All -ResourceGroup "mde-demo-rg" -VMName "demo-win11"

.EXAMPLE
    # Run interactively against the local host
    .\Start-RedTide.ps1 -Local

.EXAMPLE
    # Run a single scenario against the local host
    .\Start-RedTide.ps1 -Local -Scenario EdrDetection

.EXAMPLE
    # Preview without executing
    .\Start-RedTide.ps1 -Scenario ControlledFolder -ResourceGroup "mde-demo-rg" -VMName "demo-win11" -WhatIf

.NOTES
    Author: Carlos Suarez
    Requires (Azure mode): Az.Compute, Az.Accounts PowerShell modules
    Requires (Azure mode): RBAC role with VM Run Command permissions (Contributor or Virtual Machine Contributor)
    Target VM must: be running Windows, have the VM agent healthy, be onboarded to Defender for Endpoint
    Requires (Local mode): 64-bit Windows PowerShell 5.1+ running as Administrator, Defender Antivirus active
#>

[CmdletBinding(DefaultParameterSetName = 'Azure', SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateSet('CloudProtection', 'ControlledFolder', 'EdrDetection', 'Amsi', 'AntivirusValidation', 'BehaviorMonitoring', 'ExploitProtection', 'NetworkProtection', 'AsrRules', 'CfaTestTool', 'Pua', 'AppReputation', 'UrlReputation', 'All', 'Cleanup')]
    [string]$Scenario,

    [Parameter(ParameterSetName = 'Azure')]
    [string]$ResourceGroup,

    [Parameter(ParameterSetName = 'Azure')]
    [string]$VMName,

    [Parameter(ParameterSetName = 'Azure')]
    [string]$SubscriptionId,

    [Parameter(ParameterSetName = 'Local')]
    [switch]$Local,

    [Parameter()]
    [string]$LogPath,

    [Parameter()]
    [switch]$SkipChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Region: Color Palette
# ---------------------------------------------------------------------------

$script:Version = '1.0.0'

$script:Colors = @{
    Border   = 'DarkCyan'
    Title    = 'White'
    Body     = 'Gray'
    Menu     = 'Cyan'
    Accent   = 'Cyan'
    Running  = 'Cyan'
    Success  = 'Green'
    Warning  = 'Yellow'
    Error    = 'Red'
    Muted    = 'DarkGray'
}

# ---------------------------------------------------------------------------
# Region: Logging
# ---------------------------------------------------------------------------

$script:LogFile = $null
$script:BaselineCaptured = $false
$script:LocalMode = $false

function Initialize-LogFile {
    param([string]$Path)

    if ($Path) {
        $script:LogFile = $Path
    }
    else {
        $logDir = Join-Path $PSScriptRoot 'logs'
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $timestamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
        $script:LogFile = Join-Path $logDir "redtide-$timestamp.log"
    }

    $header = @(
        "========================================",
        "RedTide -- Log",
        "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "Host: $env:COMPUTERNAME",
        "User: $env:USERNAME",
        "========================================"
    )
    $header | Out-File -FilePath $script:LogFile -Encoding utf8
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'HH:mm:ss'
    $logLine = "[$timestamp] [$Level] $Message"

    # Log file (plain text)
    if ($script:LogFile) {
        $logLine | Out-File -FilePath $script:LogFile -Append -Encoding utf8
    }

    # Console (colored)
    switch ($Level) {
        'INFO'    { Write-Host "  [*] $Message" -ForegroundColor $script:Colors.Body }
        'WARN'    { Write-Host "  [!] $Message" -ForegroundColor $script:Colors.Warning }
        'ERROR'   { Write-Host "  [X] $Message" -ForegroundColor $script:Colors.Error }
        'SUCCESS' { Write-Host "  [+] $Message" -ForegroundColor $script:Colors.Success }
    }
}

# ---------------------------------------------------------------------------
# Region: Page Banner Helper
# ---------------------------------------------------------------------------

function Show-PageBanner {
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [ConsoleColor]$Color = 'Cyan',

        [switch]$NoClear,

        [switch]$Minor
    )

    if (-not $NoClear) { Clear-Host }

    if ($Minor) {
        $rule = [string]::new([char]0x2500, [Math]::Max(0, 56 - $Title.Length))
        Write-Host ''
        Write-Host "  $([char]0x2500)$([char]0x2500) $($Title.ToUpper()) $rule" -ForegroundColor $Color
        Write-Host ''
    }
    else {
        $termW  = try { [Console]::WindowWidth } catch { 120 }
        $cardW  = [Math]::Max(62, [Math]::Min($termW - 4, 100))
        $upper  = "   $($Title.ToUpper())   "
        $padded = $upper.PadRight([Math]::Max($upper.Length, $cardW))
        $w      = $padded.Length
        $top    = [char]0x2554 + ([string]::new([char]0x2550, $w)) + [char]0x2557
        $bot    = [char]0x255A + ([string]::new([char]0x2550, $w)) + [char]0x255D
        $mid    = [char]0x2551 + $padded + [char]0x2551

        Write-Host ''
        Write-Host "  $top" -ForegroundColor $Color
        Write-Host "  $mid" -ForegroundColor $Color
        Write-Host "  $bot" -ForegroundColor $Color
        Write-Host ''
    }
}

# ---------------------------------------------------------------------------
# Region: Interactive UI Helpers
# ---------------------------------------------------------------------------

function Show-InteractiveMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Items,
        [string]$Title,
        [int]$DefaultIndex = 0,
        [hashtable]$Commands
    )

    # ISE fallback
    if ($host.Name -eq 'Windows PowerShell ISE Host') {
        Write-Host ''
        if ($Title) { Write-Host "  $Title" -ForegroundColor $script:Colors.Title; Write-Host '' }
        $num = 0
        foreach ($item in $Items) {
            if ($null -eq $item.Value) {
                if ($item.Label) { Write-Host "  $($item.Label)" -ForegroundColor $script:Colors.Title }
                else { Write-Host '' }
            }
            else {
                $num++
                Write-Host "    $num. $($item.Label)" -ForegroundColor $script:Colors.Menu
            }
        }
        Write-Host ''
        $selectables = @($Items | Where-Object { $null -ne $_.Value })
        do {
            $in = Read-Host "  Select (1-$($selectables.Count))"
            if ($in -notmatch '^\d+$' -or [int]$in -lt 1 -or [int]$in -gt $selectables.Count) {
                Write-Host "  Invalid choice." -ForegroundColor $script:Colors.Warning
            }
        } while ($in -notmatch '^\d+$' -or [int]$in -lt 1 -or [int]$in -gt $selectables.Count)
        return $selectables[[int]$in - 1].Value
    }

    # Build selectable index map
    $selectableIndices = [System.Collections.Generic.List[int]]::new()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        if ($null -ne $Items[$i].Value) { $selectableIndices.Add($i) }
    }
    if ($selectableIndices.Count -eq 0) { return $null }

    $currentSel = [Math]::Max(0, [Math]::Min($DefaultIndex, $selectableIndices.Count - 1))
    $startTop = $host.UI.RawUI.CursorPosition.Y

    $consoleWidth = 80
    try { $consoleWidth = [Console]::WindowWidth } catch {
        try { $consoleWidth = $host.UI.RawUI.WindowSize.Width } catch {}
    }

    $cursorWasVisible = $true
    try { $cursorWasVisible = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch {}

    $totalLines = $Items.Count + 2
    if ($Title) { $totalLines += 2 }

    $render = {
        try { [Console]::SetCursorPosition(0, $startTop) } catch { return }
        if ($Title) {
            Write-Host "  $Title" -ForegroundColor $script:Colors.Title
            Write-Host ''
        }
        $highlightedRaw = $selectableIndices[$currentSel]
        $padW = [Math]::Max(10, $consoleWidth - 6)
        for ($i = 0; $i -lt $Items.Count; $i++) {
            $item = $Items[$i]
            $isHeader = ($null -eq $item.Value)
            $label = $item.Label
            if ($isHeader -and -not $label) { Write-Host ''; continue }
            $displayLabel = if ($label.Length -gt $padW) { $label.Substring(0, $padW) } else { $label }
            $pad = $displayLabel.PadRight($padW)
            if ($isHeader) {
                Write-Host "  $pad" -ForegroundColor $script:Colors.Title
            }
            elseif ($i -eq $highlightedRaw) {
                Write-Host '  > ' -NoNewline -ForegroundColor Cyan
                Write-Host $pad -ForegroundColor Black -BackgroundColor Cyan
            }
            else {
                Write-Host "    $pad" -ForegroundColor $script:Colors.Menu
            }
        }
        Write-Host ''
        $hintLine = '  [Up/Down] Navigate   [Enter] Select   [Esc] Back   [1-9] Jump'
        if ($Commands) {
            $cmdHints = ($Commands.GetEnumerator() | Sort-Object Key | ForEach-Object {
                $display = if ($_.Key -eq 'Oem2') { '?' } else { $_.Key }
                "[$display] $($_.Value)"
            }) -join '   '
            $hintLine += "   $cmdHints"
        }
        Write-Host $hintLine -ForegroundColor $script:Colors.Muted
    }

    & $render
    # Recalculate startTop in case console scrolled during first render
    $startTop = [Math]::Max(0, $host.UI.RawUI.CursorPosition.Y - $totalLines)

    $result = $null
    $done = $false
    while (-not $done) {
        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            'UpArrow'    { if ($currentSel -gt 0) { $currentSel-- }; & $render }
            'DownArrow'  { if ($currentSel -lt ($selectableIndices.Count - 1)) { $currentSel++ }; & $render }
            'Home'       { $currentSel = 0; & $render }
            'End'        { $currentSel = $selectableIndices.Count - 1; & $render }
            'Enter'      { $result = $Items[$selectableIndices[$currentSel]].Value; $done = $true }
            'Escape'     { $result = $null; $done = $true }
            default {
                $ch = $key.KeyChar
                if ($ch -ge '1' -and $ch -le '9') {
                    $num = [int][string]$ch - 1
                    if ($num -lt $selectableIndices.Count) { $currentSel = $num; & $render }
                }
                elseif ($ch -eq 'q' -or $ch -eq 'Q') { $result = $null; $done = $true }
                elseif ($Commands -and $Commands.ContainsKey([string]$key.Key)) {
                    $result = $Commands[[string]$key.Key]; $done = $true
                }
            }
        }
    }

    try { [Console]::CursorVisible = $cursorWasVisible } catch {}
    try { [Console]::SetCursorPosition(0, $startTop + $totalLines) } catch {}
    return $result
}

function Show-Confirmation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,

        [ValidateSet('Yes', 'No')]
        [string]$Default = 'Yes'
    )

    # ISE fallback
    if ($host.Name -eq 'Windows PowerShell ISE Host') {
        $r = Read-Host "  $Prompt (Y/n)"
        return ($r.Trim() -eq '' -or $r.Trim() -match '^[Yy]')
    }

    $onYes = ($Default -eq 'Yes')
    $lineTop = $host.UI.RawUI.CursorPosition.Y
    try { [Console]::CursorVisible = $false } catch {}

    $renderLine = {
        try { [Console]::SetCursorPosition(0, $lineTop) } catch { return }
        Write-Host "  $Prompt  " -NoNewline -ForegroundColor $script:Colors.Title
        if ($onYes) {
            Write-Host '[' -NoNewline -ForegroundColor $script:Colors.Muted
            Write-Host ' Yes ' -NoNewline -ForegroundColor Black -BackgroundColor Cyan
            Write-Host ']' -NoNewline -ForegroundColor $script:Colors.Muted
            Write-Host '  [ No ]' -NoNewline -ForegroundColor $script:Colors.Muted
        }
        else {
            Write-Host '[ Yes ]  ' -NoNewline -ForegroundColor $script:Colors.Muted
            Write-Host '[' -NoNewline -ForegroundColor $script:Colors.Muted
            Write-Host ' No ' -NoNewline -ForegroundColor Black -BackgroundColor Cyan
            Write-Host ']' -NoNewline -ForegroundColor $script:Colors.Muted
        }
        Write-Host '   ' -NoNewline
        Write-Host ''
    }

    & $renderLine

    $done = $false
    while (-not $done) {
        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            'LeftArrow'  { $onYes = $true;  & $renderLine }
            'RightArrow' { $onYes = $false; & $renderLine }
            'Enter'      { $done = $true }
            'Escape'     { $onYes = $null; $done = $true }
            'Y'          { $onYes = $true;  $done = $true }
            'N'          { $onYes = $false; $done = $true }
            default      {}
        }
    }

    Write-Host ''
    try { [Console]::CursorVisible = $true } catch {}
    if ($null -eq $onYes) { return $null }
    return $onYes
}

function Show-InputWithValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,

        [scriptblock]$Validate = { param($v) $v.Trim() -ne '' },

        [string]$ErrorMessage = 'Invalid input. Try again.'
    )

    while ($true) {
        $value = Read-Host "  $Prompt"
        if (& $Validate $value) { return $value.Trim() }

        $errPos = $host.UI.RawUI.CursorPosition
        Write-Host "  $ErrorMessage" -ForegroundColor $script:Colors.Error -NoNewline
        Start-Sleep -Milliseconds 1500
        try {
            [Console]::SetCursorPosition(0, $errPos.Y)
            Write-Host (' ' * ([Console]::WindowWidth - 1))
            [Console]::SetCursorPosition(0, $errPos.Y)
        } catch { Write-Host '' }
    }
}

function Write-CheckResult {
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [ValidateSet('pass', 'fail', 'warn')]
        [string]$Status,

        [string]$Detail = ''
    )
    $maxWidth = 45
    $dots = '.' * [Math]::Max(3, $maxWidth - $Label.Length)
    $symbol = switch ($Status) {
        'pass' { '[+]' }
        'fail' { '[X]' }
        'warn' { '[!]' }
    }
    $color = switch ($Status) {
        'pass' { $script:Colors.Success }
        'fail' { $script:Colors.Error }
        'warn' { $script:Colors.Warning }
    }
    Write-Host "  $Label $dots " -NoNewline -ForegroundColor $script:Colors.Body
    Write-Host "$symbol $Detail" -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# Region: Pre-flight Checks
# ---------------------------------------------------------------------------

function Test-Prerequisites {
    Show-PageBanner -Title 'Pre-flight Checks' -Color Cyan
    Write-Log 'Running pre-flight checks...'

    # 1. Check required PowerShell modules
    $missingModules = @()
    foreach ($mod in @('Az.Accounts', 'Az.Compute')) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $missingModules += $mod
        }
    }
    if ($missingModules.Count -gt 0) {
        Write-Log "Missing PowerShell modules: $($missingModules -join ', ')" -Level ERROR
        Write-Host ''
        Write-Host '  The Az PowerShell module is required to run commands on Azure VMs.' -ForegroundColor Yellow
        Write-Host '  Install it with:' -ForegroundColor Yellow
        Write-Host '    Install-Module -Name Az -Scope CurrentUser -Force' -ForegroundColor Cyan
        Write-Host ''
        $installNow = Read-Host '  Install now? (Y/n)'
        if ($installNow.Trim() -eq '' -or $installNow.Trim() -match '^[Yy]') {
            Write-Log 'Installing Az module (this may take a few minutes)...'
            try {
                Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Log 'Az module installed. Importing...' -Level SUCCESS
                Import-Module Az.Accounts -ErrorAction Stop
                Import-Module Az.Compute -ErrorAction Stop
                Write-Log 'Az modules imported.' -Level SUCCESS
            }
            catch {
                Write-Log "Install failed: $_" -Level ERROR
                Write-Log 'Try running PowerShell as Administrator and install manually.' -Level WARN
                return $false
            }
        }
        else {
            return $false
        }
    }
    Write-Log 'Required modules (Az.Accounts, Az.Compute): installed.' -Level SUCCESS

    # 2. Check Az context
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-Log 'Not logged into Azure. Launching sign-in...' -Level WARN
        Write-Host ''
        Write-Host '  You need to sign in to Azure. A browser window will open.' -ForegroundColor Yellow
        Write-Host '  Press Enter to continue...' -ForegroundColor Yellow
        Read-Host | Out-Null
        try {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $context = Get-AzContext
            if (-not $context) {
                Write-Log 'Sign-in did not complete. Run Connect-AzAccount manually and try again.' -Level ERROR
                return $false
            }
            Write-Log "Signed in as: $($context.Account.Id)" -Level SUCCESS
        }
        catch {
            Write-Log "Sign-in failed: $_" -Level ERROR
            Write-Log 'Run Connect-AzAccount manually and try again.' -Level WARN
            return $false
        }
    }
    Write-Log "Azure context: $($context.Account.Id) | Subscription: $($context.Subscription.Name)" -Level SUCCESS

    # 3. Switch subscription if needed
    if ($script:SubscriptionId -and $context.Subscription.Id -ne $script:SubscriptionId) {
        Write-Log "Switching to subscription: $($script:SubscriptionId)"
        try {
            Set-AzContext -SubscriptionId $script:SubscriptionId -ErrorAction Stop | Out-Null
            Write-Log 'Subscription switched.' -Level SUCCESS
        }
        catch {
            Write-Log "Failed to switch subscription: $_" -Level ERROR
            return $false
        }
    }

    # 4. Check resource group exists
    $rgValid = $false
    while (-not $rgValid) {
        try {
            Get-AzResourceGroup -Name $script:ResourceGroup -ErrorAction Stop | Out-Null
            Write-Log "Resource group '$($script:ResourceGroup)' found." -Level SUCCESS
            $rgValid = $true
        }
        catch {
            Write-Log "Resource group '$($script:ResourceGroup)' not found in this subscription." -Level ERROR
            $retry = Read-Host '  Enter a different resource group name (or press Enter to abort)'
            if (-not $retry.Trim()) { return $false }
            $script:ResourceGroup = $retry.Trim()
        }
    }

    # 5. Check VM exists
    $vmValid = $false
    while (-not $vmValid) {
        try {
            $script:VM = Get-AzVM -ResourceGroupName $script:ResourceGroup -Name $script:VMName -Status -ErrorAction Stop
            $vmValid = $true
        }
        catch {
            Write-Log "VM '$($script:VMName)' not found in resource group '$($script:ResourceGroup)'." -Level ERROR
            $retry = Read-Host '  Enter a different VM name (or press Enter to abort)'
            if (-not $retry.Trim()) { return $false }
            $script:VMName = $retry.Trim()
        }
    }

    # 6. Check VM is running
    $powerState = ($script:VM.Statuses | Where-Object { $_.Code -like 'PowerState/*' }).DisplayStatus
    if ($powerState -ne 'VM running') {
        Write-Log "VM is not running. Current state: $powerState" -Level ERROR
        Write-Host ''
        Write-Host '  The VM must be running to deploy simulations.' -ForegroundColor Yellow
        $startNow = Read-Host '  Start the VM now? (Y/n)'
        if ($startNow.Trim() -eq '' -or $startNow.Trim() -match '^[Yy]') {
            Write-Log "Starting VM '$($script:VMName)' (this may take a few minutes)..."
            try {
                Start-AzVM -ResourceGroupName $script:ResourceGroup -Name $script:VMName -ErrorAction Stop | Out-Null
                Write-Log 'VM started.' -Level SUCCESS
                $script:VM = Get-AzVM -ResourceGroupName $script:ResourceGroup -Name $script:VMName -Status -ErrorAction Stop
            }
            catch {
                Write-Log "Failed to start VM: $_" -Level ERROR
                return $false
            }
        }
        else {
            Write-Log "Start the VM with: Start-AzVM -ResourceGroupName '$($script:ResourceGroup)' -Name '$($script:VMName)'" -Level WARN
            return $false
        }
    }
    Write-Log "VM '$($script:VMName)' is running." -Level SUCCESS

    # 7. Check VM agent status
    $agentStatus = ($script:VM.Statuses | Where-Object { $_.Code -like 'ProvisioningState/*' }).DisplayStatus
    if ($agentStatus) {
        Write-Log "VM provisioning state: $agentStatus" -Level INFO
    }

    # 8. Check OS type
    $vmDetail = Get-AzVM -ResourceGroupName $script:ResourceGroup -Name $script:VMName -ErrorAction Stop
    $osType = $vmDetail.StorageProfile.OsDisk.OsType
    if ($osType -ne 'Windows') {
        Write-Log "VM OS is '$osType'. These simulations require Windows." -Level ERROR
        return $false
    }
    Write-Log "VM OS: Windows" -Level SUCCESS

    # 9. Test RunCommand permission (RBAC check)
    $rbacRG = $script:ResourceGroup
    $rbacVM = $script:VMName
    try {
        $rbacBlock = [scriptblock]::Create(@"
            Import-Module Az.Compute -ErrorAction Stop
            `$r = Invoke-AzVMRunCommand ``
                -ResourceGroupName '$($rbacRG -replace "'","''")' ``
                -VMName '$($rbacVM -replace "'","''")' ``
                -CommandId 'RunPowerShellScript' ``
                -ScriptString 'Write-Output "OK"' ``
                -ErrorAction Stop
            (`$r.Value | Where-Object { `$_.Code -eq 'ComponentStatus/StdOut/succeeded' }).Message
"@)
        $testOutput = Invoke-WithSpinner -Label 'Testing RunCommand permission (RBAC)' -ScriptBlock $rbacBlock

        if ($testOutput -match 'OK') {
            Write-Log 'RunCommand permission verified.' -Level SUCCESS
        }
        else {
            Write-Log 'RunCommand returned unexpected output. VM agent may be unhealthy.' -Level ERROR
            return $false
        }
    }
    catch {
        if ($_.Exception.Message -match 'AuthorizationFailed|does not have authorization|Forbidden') {
            Write-Log "Permission denied: your account cannot run commands on this VM." -Level ERROR
            Write-Log "Required: Contributor or Virtual Machine Contributor role on resource group '$($script:ResourceGroup)'." -Level WARN
            Write-Log "Grant access: New-AzRoleAssignment -SignInName '<your-email>' -RoleDefinitionName 'Virtual Machine Contributor' -ResourceGroupName '$($script:ResourceGroup)'" -Level WARN
        }
        else {
            Write-Log "RunCommand test failed: $_" -Level ERROR
            Write-Log 'The VM agent may be unhealthy or the VM may not be fully started. Try again in a minute.' -Level WARN
        }
        return $false
    }

    Write-Log 'All pre-flight checks passed.' -Level SUCCESS
    return $true
}

# ---------------------------------------------------------------------------
# Region: VM Readiness (MDE-specific checks on the remote VM)
# ---------------------------------------------------------------------------

function Test-VmReadiness {
    Show-PageBanner -Title 'VM Readiness' -Color Cyan -NoClear
    Write-Log 'Checking MDE readiness on the VM...'

    # Minimal script: only service checks (no network probes that trigger
    # Defender behavioral alerts and create noise in the demo portal)
    $readinessScript = @'
        $results = @{}

        # 1. Defender Antivirus service
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
            $results['DefenderService'] = $status.AMServiceEnabled
            $results['RealTimeProtection'] = $status.RealTimeProtectionEnabled
            $results['BehaviorMonitoring'] = $status.BehaviorMonitorEnabled
            $results['AntivirusSignatureAge'] = $status.AntivirusSignatureAge
        }
        catch {
            $results['DefenderService'] = $false
            $results['RealTimeProtection'] = $false
            $results['BehaviorMonitoring'] = $false
            $results['DefenderError'] = $_.Exception.Message
        }

        # 2. MDE onboarding (Sense service)
        $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
        if ($sense) {
            $results['SenseRunning'] = ($sense.Status -eq 'Running')
            $results['SenseStatus'] = $sense.Status.ToString()
        }
        else {
            $results['SenseRunning'] = $false
            $results['SenseStatus'] = 'NotInstalled'
        }

        # Output as key=value pairs for easy parsing
        foreach ($key in $results.Keys) {
            Write-Output "$key=$($results[$key])"
        }
'@

    try {
        # Save readiness script to temp file so the job can read it
        $readinessFile = [System.IO.Path]::GetTempFileName()
        Set-Content -Path $readinessFile -Value $readinessScript -Encoding UTF8

        $readinessBlock = [scriptblock]::Create(@"
            Import-Module Az.Compute -ErrorAction Stop
            `$scriptText = Get-Content -Path '$($readinessFile -replace "\\","\\")' -Raw
            `$r = Invoke-AzVMRunCommand ``
                -ResourceGroupName '$($script:ResourceGroup -replace "'","''")' ``
                -VMName '$($script:VMName -replace "'","''")' ``
                -CommandId 'RunPowerShellScript' ``
                -ScriptString `$scriptText ``
                -ErrorAction Stop
            (`$r.Value | Where-Object { `$_.Code -eq 'ComponentStatus/StdOut/succeeded' }).Message
"@)
        $output = Invoke-WithSpinner -Label 'Checking MDE readiness on VM' -ScriptBlock $readinessBlock
        Remove-Item $readinessFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        Remove-Item $readinessFile -Force -ErrorAction SilentlyContinue
        Write-Log "VM readiness check failed: $_" -Level ERROR
        return $false
    }

    if (-not $output) {
        Write-Log 'VM readiness check returned no output. VM agent may be unhealthy.' -Level ERROR
        return $false
    }

    # Parse key=value pairs
    $checks = @{}
    foreach ($line in ($output -split "`n")) {
        $line = $line.Trim()
        if ($line -match '^(\w+)=(.*)$') {
            $checks[$Matches[1]] = $Matches[2]
        }
    }

    $allPassed = $true

    # Defender Antivirus
    if ($checks['DefenderService'] -eq 'True') {
        Write-Log 'Defender Antivirus service: running.' -Level SUCCESS
    }
    else {
        Write-Log 'Defender Antivirus service is NOT running.' -Level ERROR
        if ($checks['DefenderError']) {
            Write-Log "  Error: $($checks['DefenderError'])" -Level WARN
        }
        Write-Log '  Fix: Check that the VM is not running a third-party AV in active mode.' -Level WARN
        $allPassed = $false
    }

    # Real-time protection
    if ($checks['RealTimeProtection'] -eq 'True') {
        Write-Log 'Real-time protection: enabled.' -Level SUCCESS
    }
    else {
        Write-Log 'Real-time protection is DISABLED.' -Level ERROR
        Write-Log '  Fix on VM: Set-MpPreference -DisableRealtimeMonitoring $false' -Level WARN
        $allPassed = $false
    }

    # Behavior monitoring
    if ($checks['BehaviorMonitoring'] -eq 'True') {
        Write-Log 'Behavior monitoring: enabled.' -Level SUCCESS
    }
    else {
        Write-Log 'Behavior monitoring is DISABLED.' -Level WARN
        Write-Log '  Fix on VM: Set-MpPreference -DisableBehaviorMonitoring $false' -Level WARN
        Write-Log '  (Required for AMSI and Behavior Monitoring simulations.)' -Level WARN
    }

    # Signature age
    if ($checks['AntivirusSignatureAge']) {
        $sigAge = [int]$checks['AntivirusSignatureAge']
        if ($sigAge -le 3) {
            Write-Log "Antivirus signatures: $sigAge day(s) old." -Level SUCCESS
        }
        else {
            Write-Log "Antivirus signatures are $sigAge days old." -Level WARN
            Write-Log '  Fix on VM: Update-MpSignature' -Level WARN
        }
    }

    # MDE onboarding (Sense)
    if ($checks['SenseRunning'] -eq 'True') {
        Write-Log 'MDE onboarding (Sense service): running.' -Level SUCCESS
    }
    else {
        $senseStatus = $checks['SenseStatus']
        if ($senseStatus -eq 'NotInstalled') {
            Write-Log 'MDE is NOT onboarded -- Sense service not installed.' -Level ERROR
            Write-Log '  Fix: Onboard the device at security.microsoft.com > Settings > Endpoints > Onboarding.' -Level WARN
        }
        else {
            Write-Log "MDE Sense service is $senseStatus (not running)." -Level ERROR
            Write-Log '  Fix on VM: Start-Service -Name Sense' -Level WARN
        }
        $allPassed = $false
    }

    if ($allPassed) {
        Write-Log 'VM is ready for all simulations.' -Level SUCCESS
    }
    else {
        Write-Log 'VM has issues that may affect simulations. See warnings above.' -Level WARN
    }

    return $allPassed
}

# ---------------------------------------------------------------------------
# Region: Spinner Helper
# ---------------------------------------------------------------------------

function Invoke-WithSpinner {
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [int]$TimeoutSeconds = 300
    )

    Write-Host "  $Label " -ForegroundColor Cyan -NoNewline

    # Save Az context so the job can authenticate
    $ctxFile = $null
    try {
        $ctxFile = [System.IO.Path]::GetTempFileName()
        Save-AzContext -Path $ctxFile -Force -ErrorAction Stop | Out-Null
    }
    catch {
        # If context save fails, still try without it
        $ctxFile = $null
    }

    # Inject Az context import at the top of the scriptblock
    if ($ctxFile) {
        $wrappedBlock = [scriptblock]::Create(@"
            Import-Module Az.Accounts -ErrorAction SilentlyContinue
            Import-AzContext -Path '$ctxFile' -ErrorAction SilentlyContinue | Out-Null
            & { $ScriptBlock }
"@)
        $job = Start-Job -ScriptBlock $wrappedBlock
    }
    else {
        $job = Start-Job -ScriptBlock $ScriptBlock
    }

    try {
    $spinChars = @('|', '/', '-', '\')
    $spinIndex = 0

    while ($job.State -eq 'Running') {
        $char = $spinChars[$spinIndex % $spinChars.Count]
        $elapsed = [math]::Floor(((Get-Date) - $job.PSBeginTime).TotalSeconds)
        Write-Host "`r  $Label $char (${elapsed}s) " -ForegroundColor Cyan -NoNewline
        Start-Sleep -Milliseconds 250
        $spinIndex++

        if ($elapsed -ge $TimeoutSeconds) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            if ($ctxFile) { Remove-Item $ctxFile -Force -ErrorAction SilentlyContinue }
            $dots = '.' * [Math]::Max(3, 45 - $Label.Length)
            Write-Host "`r  $Label $dots [!] TIMEOUT (${TimeoutSeconds}s)       " -ForegroundColor $script:Colors.Error
            throw "Timeout after ${TimeoutSeconds}s: $Label"
        }
    }

    $elapsed = [math]::Floor(((Get-Date) - $job.PSBeginTime).TotalSeconds)
    if ($ctxFile) { Remove-Item $ctxFile -Force -ErrorAction SilentlyContinue }

    if ($job.State -eq 'Failed') {
        $err = $job.ChildJobs[0].JobStateInfo.Reason
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        $dots = '.' * [Math]::Max(3, 45 - $Label.Length)
        Write-Host "`r  $Label $dots [X] FAILED (${elapsed}s)       " -ForegroundColor $script:Colors.Error
        throw $err
    }

    $result = Receive-Job -Job $job -ErrorAction Stop
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    $dots = '.' * [Math]::Max(3, 45 - $Label.Length)
    Write-Host "`r  $Label $dots [+] OK (${elapsed}s)         " -ForegroundColor $script:Colors.Success
    return $result
    }
    finally {
        if ($ctxFile -and (Test-Path $ctxFile)) {
            Remove-Item $ctxFile -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# Region: VM Command Execution
# ---------------------------------------------------------------------------

function Invoke-DemoCommand {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [string]$ScriptContent,

        [int]$TimeoutSeconds = 300,

        [switch]$ExpectErrors
    )

    Write-Host "  $Description " -ForegroundColor Cyan -NoNewline

    # Log script content to file only (not the console)
    if ($script:LogFile) {
        $timestamp = Get-Date -Format 'HH:mm:ss'
        "[$timestamp] [INFO] Executing: $Description" | Out-File -FilePath $script:LogFile -Append -Encoding utf8
        "[$timestamp] [INFO] Script:`n$ScriptContent" | Out-File -FilePath $script:LogFile -Append -Encoding utf8
    }

    if (-not $PSCmdlet.ShouldProcess($script:VMName, $Description)) {
        Write-Host ''
        Write-Log "WhatIf: Would execute '$Description' on $($script:VMName)" -Level WARN
        return @{ Success = $true; Output = 'WhatIf mode -- no execution' }
    }

    try {
        if ($script:LocalMode) {
            # ----- Local mode: run the script directly in a background job -----
            $ctxFile = $null
            $job = Start-Job -ScriptBlock {
                param($Script)
                $outBuilder = [System.Text.StringBuilder]::new()
                $errBuilder = [System.Text.StringBuilder]::new()
                try {
                    $sb = [scriptblock]::Create($Script)
                    # *>&1 captures all streams (output, error, warning, info, verbose, debug)
                    & $sb *>&1 | ForEach-Object {
                        if ($_ -is [System.Management.Automation.ErrorRecord]) {
                            [void]$errBuilder.AppendLine($_.ToString())
                        }
                        elseif ($_ -is [System.Management.Automation.WarningRecord]) {
                            [void]$errBuilder.AppendLine("WARNING: $($_.Message)")
                        }
                        else {
                            [void]$outBuilder.AppendLine($_.ToString())
                        }
                    }
                }
                catch {
                    [void]$errBuilder.AppendLine($_.Exception.Message)
                }
                # Strip NUL and other non-printable control chars. Any of these
                # in the returned strings breaks CLIXML serialization across the
                # Start-Job boundary and causes Receive-Job to throw
                # "Cannot process an element with node type Text".
                $out = [regex]::Replace($outBuilder.ToString(), '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
                $err = [regex]::Replace($errBuilder.ToString(), '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
                [PSCustomObject]@{ StdOut = $out; StdErr = $err }
            } -ArgumentList $ScriptContent
        }
        else {
            # ----- Azure mode: run via Invoke-AzVMRunCommand -----
            # Save Az context so the background job can authenticate
            $ctxFile = [System.IO.Path]::GetTempFileName()
            Save-AzContext -Path $ctxFile -Force -ErrorAction Stop | Out-Null

            # Run as background job so we can show a spinner.
            # Extract stdout/stderr INSIDE the job to avoid PS 5.1 deserialization issues
            # (deserialized objects lose nested property access with StrictMode).
            $job = Start-Job -ScriptBlock {
                param($RG, $VM, $Script, $CtxPath)
                Import-Module Az.Accounts -ErrorAction Stop
                Import-Module Az.Compute -ErrorAction Stop
                Import-AzContext -Path $CtxPath -ErrorAction Stop | Out-Null

                $r = Invoke-AzVMRunCommand `
                    -ResourceGroupName $RG `
                    -VMName $VM `
                    -CommandId 'RunPowerShellScript' `
                    -ScriptString $Script `
                    -ErrorAction Stop

                # Return plain strings so deserialization is safe. Strip NUL and
                # other non-printable control chars -- any of these break CLIXML
                # serialization across the Start-Job boundary and cause
                # Receive-Job to throw "Cannot process an element with node type Text".
                $stdout = ($r.Value | Where-Object { $_.Code -eq 'ComponentStatus/StdOut/succeeded' }).Message
                $stderr = ($r.Value | Where-Object { $_.Code -eq 'ComponentStatus/StdErr/succeeded' }).Message
                $stdout = [regex]::Replace([string]$stdout, '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
                $stderr = [regex]::Replace([string]$stderr, '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
                [PSCustomObject]@{ StdOut = $stdout; StdErr = $stderr }
            } -ArgumentList $script:ResourceGroup, $script:VMName, $ScriptContent, $ctxFile
        }

        # Spinner animation while job runs
        $spinChars = @('|', '/', '-', '\')
        $spinIndex = 0
        $elapsed = 0
        while ($job.State -eq 'Running') {
            $char = $spinChars[$spinIndex % $spinChars.Count]
            $timeLabel = $(if ($elapsed -lt 60) { "${elapsed}s" } else { "$([math]::Floor($elapsed / 60))m $($elapsed % 60)s" })
            Write-Host "`r  $Description $char ($timeLabel) " -ForegroundColor Cyan -NoNewline
            Start-Sleep -Milliseconds 250
            $spinIndex++
            $elapsed = [math]::Floor(((Get-Date) - $job.PSBeginTime).TotalSeconds)

            if ($elapsed -ge $TimeoutSeconds) {
                Stop-Job -Job $job -ErrorAction SilentlyContinue
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                if ($ctxFile) { Remove-Item $ctxFile -Force -ErrorAction SilentlyContinue }
                Write-Host "`r  $Description [TIMEOUT after ${TimeoutSeconds}s]       " -ForegroundColor Red
                Write-Host ''
                if ($script:LogFile) {
                    $ts = Get-Date -Format 'HH:mm:ss'
                    "[$ts] [ERROR] Timeout after ${TimeoutSeconds}s: $Description" | Out-File -FilePath $script:LogFile -Append -Encoding utf8
                }
                return @{ Success = $false; Output = ''; Errors = "Timeout after ${TimeoutSeconds}s" }
            }
        }

        # Clean up context file
        if ($ctxFile) { Remove-Item $ctxFile -Force -ErrorAction SilentlyContinue }

        # Get result -- job returns a PSCustomObject with StdOut/StdErr strings.
        # Tolerate CLIXML deserialization errors ("Cannot process an element with
        # node type Text") that can occur when a child process writes raw bytes
        # to the host channel. The job itself still completed; we just lose its
        # captured output. Treat as a soft warning so the scenario can continue.
        $jobResult = $null
        $receiveError = $null
        try {
            $jobResult = Receive-Job -Job $job -ErrorAction Stop
        }
        catch {
            $receiveError = $_.Exception.Message
            if ($script:LogFile) {
                $ts = Get-Date -Format 'HH:mm:ss'
                "[$ts] [WARN] Receive-Job CLIXML error (job state=$($job.State)): $receiveError" |
                    Out-File -FilePath $script:LogFile -Append -Encoding utf8
            }
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

        if ($jobResult) {
            $output = $jobResult.StdOut
            $errors = $jobResult.StdErr
        }
        else {
            $output = ''
            $errors = if ($receiveError) {
                "Output capture failed (background process CLIXML error): $receiveError"
            } else {
                ''
            }
        }

        if ($errors) {
            if ($script:LogFile) {
                $ts = Get-Date -Format 'HH:mm:ss'
                "[$ts] [WARN] StdErr: $errors" | Out-File -FilePath $script:LogFile -Append -Encoding utf8
            }
            if ($ExpectErrors) {
                # Show a short confirmation instead of raw error dump
                if ($errors -match 'ScriptContainedMaliciousContent|blocked by your antivirus') {
                    Write-Host "    Detection confirmed: script was blocked by antivirus (expected)." -ForegroundColor Green
                }
                else {
                    Write-Host "    Errors occurred (expected for this test). Details in log file." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "  [!] StdErr (see log for details)" -ForegroundColor Yellow
            }
        }

        # Log full output to file only
        if ($output -and $script:LogFile) {
            $ts = Get-Date -Format 'HH:mm:ss'
            "[$ts] [INFO] Output: $output" | Out-File -FilePath $script:LogFile -Append -Encoding utf8
        }

        $timeLabel = $(if ($elapsed -lt 60) { "${elapsed}s" } else { "$([math]::Floor($elapsed / 60))m $($elapsed % 60)s" })
        Write-Host "`r  $Description [done] ($timeLabel)       " -ForegroundColor Green
        return @{ Success = $true; Output = $output; Errors = $errors }
    }
    catch {
        Write-Host "`r  $Description [FAILED]                   " -ForegroundColor Red
        Write-Host "    $_" -ForegroundColor Red
        if ($script:LogFile) {
            $ts = Get-Date -Format 'HH:mm:ss'
            "[$ts] [ERROR] Failed: $Description -- $_" | Out-File -FilePath $script:LogFile -Append -Encoding utf8
        }
        # Clean up job if it exists
        if ($job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
        if ($ctxFile) { Remove-Item $ctxFile -Force -ErrorAction SilentlyContinue }
        return @{ Success = $false; Output = ''; Errors = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
# Region: Interactive Menu
# ---------------------------------------------------------------------------

function Show-Menu {
    Clear-Host
    Write-Host ''
    Write-Host '        ____           _ _____ _     _      ' -ForegroundColor Red
    Write-Host '       |  _ \ ___  __| |_   _(_) __| | ___ ' -ForegroundColor Red
    Write-Host '       | |_) / _ \/ _` | | | | |/ _` |/ _ \' -ForegroundColor Red
    Write-Host '       |  _ <  __/ (_| | | | | | (_| |  __/' -ForegroundColor Red
    Write-Host '       |_| \_\___|\__,_| |_| |_|\__,_|\___|' -ForegroundColor Red
    Write-Host ''
    Write-Host '       Attack Simulations for Endpoint Protection' -ForegroundColor DarkGray
    Write-Host ''

    $items = @(
        @{ Label = 'NEXT-GENERATION PROTECTION (P1+)';                 Value = $null }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 1.  Cloud-Delivered Protection";               Value = 'CloudProtection' }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 2.  AMSI Script Detection";                    Value = 'Amsi' }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 3.  Antivirus Validation (EICAR)";             Value = 'AntivirusValidation' }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 4.  Behavior Monitoring";                      Value = 'BehaviorMonitoring' }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 5.  PUA Detection (Unwanted Apps)";            Value = 'Pua' }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 6.  SmartScreen App Reputation       [Edge]";  Value = 'AppReputation' }
        @{ Label = "  $([char]0x2514)$([char]0x2500)$([char]0x2500) 7.  SmartScreen URL Reputation       [Edge]";  Value = 'UrlReputation' }
        @{ Label = '';                                                  Value = $null }
        @{ Label = 'ATTACK SURFACE REDUCTION (P1+)';                    Value = $null }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 8.  Controlled Folder Access    [Ransomware]"; Value = 'ControlledFolder' }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 9.  ASR Rules                        [RDP]";   Value = 'AsrRules' }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 10. CFA Test Tool                    [RDP]";   Value = 'CfaTestTool' }
        @{ Label = "  $([char]0x251C)$([char]0x2500)$([char]0x2500) 11. Exploit Protection            [Config]";   Value = 'ExploitProtection' }
        @{ Label = "  $([char]0x2514)$([char]0x2500)$([char]0x2500) 12. Network Protection";                       Value = 'NetworkProtection' }
        @{ Label = '';                                                  Value = $null }
        @{ Label = 'ENDPOINT DETECTION & RESPONSE (P2 Only)';           Value = $null }
        @{ Label = "  $([char]0x2514)$([char]0x2500)$([char]0x2500) 13. EDR Detection Test";                       Value = 'EdrDetection' }
        @{ Label = '';                                                  Value = $null }
        @{ Label = "$([string]::new([char]0x2500, 60))";                Value = $null }
        @{ Label = '  A.  Deploy ALL simulations';                      Value = 'All' }
        @{ Label = '  B.  Back to main page';                           Value = 'MainPage' }
        @{ Label = '  C.  Clean up all simulations';                    Value = 'Cleanup' }
        @{ Label = '  X.  Exit';                                        Value = 'Exit' }
    )

    $result = Show-InteractiveMenu -Items $items
    if ($null -eq $result) { return 'Exit' }
    return $result
}

function Read-VMInfo {
    if (-not $script:ResourceGroup -or -not $script:VMName) {
        Show-PageBanner -Title 'VM Configuration' -Color Cyan

        Write-Host '  RedTide runs attack simulations on an Azure VM.' -ForegroundColor Gray
        Write-Host '  Enter the Azure resource group and VM name where' -ForegroundColor Gray
        Write-Host '  the simulations will be deployed.' -ForegroundColor Gray
        Write-Host ''
    }
    if (-not $script:ResourceGroup) {
        $script:ResourceGroup = Show-InputWithValidation -Prompt 'Resource Group' `
            -Validate { param($v) $v.Trim() -match '^[a-zA-Z0-9._-]+$' } `
            -ErrorMessage 'Must contain only letters, numbers, dots, hyphens, or underscores.'
    }
    if (-not $script:VMName) {
        $script:VMName = Show-InputWithValidation -Prompt 'VM Name' `
            -Validate { param($v) $v.Trim() -match '^[a-zA-Z0-9-]+$' } `
            -ErrorMessage 'Must contain only letters, numbers, or hyphens.'
    }
}

function Test-VMConnection {
    Show-PageBanner -Title 'Verifying Connection' -Color Cyan

    Write-Host '  Checking prerequisites, VM status, and permissions...' -ForegroundColor Gray
    Write-Host ''

    # ---- Prerequisite checks (Az modules + login) ----
    $issues = @()

    # Check Az modules
    $missingModules = @()
    foreach ($mod in @('Az.Accounts', 'Az.Compute')) {
        if (-not (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)) {
            $missingModules += $mod
        }
    }
    if ($missingModules.Count -gt 0) {
        Write-CheckResult -Label 'Az PowerShell modules' -Status 'fail' -Detail "Missing: $($missingModules -join ', ')"
        $issues += "Missing modules: $($missingModules -join ', '). Install with: Install-Module -Name Az -Scope CurrentUser -Force"
    } else {
        Write-CheckResult -Label 'Az PowerShell modules' -Status 'pass' -Detail 'Installed'
    }

    # Check Azure login
    $context = $null
    if ($missingModules.Count -eq 0) {
        try {
            $context = Get-AzContext -ErrorAction Stop
            if (-not $context -or -not $context.Account) {
                Write-CheckResult -Label 'Azure login' -Status 'fail' -Detail 'Not signed in'
                $issues += 'Not signed in to Azure. Run Connect-AzAccount to sign in.'
            } else {
                Write-CheckResult -Label 'Azure login' -Status 'pass' -Detail $context.Account.Id
            }
        }
        catch {
            Write-CheckResult -Label 'Azure login' -Status 'fail' -Detail 'Not signed in'
            $issues += 'Not signed in to Azure. Run Connect-AzAccount to sign in.'
        }
    } else {
        Write-CheckResult -Label 'Azure login' -Status 'warn' -Detail 'Cannot check (modules missing)'
        $issues += 'Cannot verify Azure login without Az modules.'
    }

    # If prerequisites failed, show summary and offer pre-flight
    if ($issues.Count -gt 0) {
        Write-Host ''
        Write-Host '  MISSING REQUIREMENTS' -ForegroundColor $script:Colors.Warning
        Write-Host "  $([string]::new([char]0x2500, 40))" -ForegroundColor $script:Colors.Warning
        Write-Host ''
        foreach ($issue in $issues) {
            Write-Host "    - $issue" -ForegroundColor Gray
        }
        Write-Host ''

        $fixItems = @(
            @{ Label = 'Run pre-flight checks (will fix these issues)'; Value = 'PreFlight' }
            @{ Label = $null; Value = $null }
            @{ Label = 'Exit'; Value = 'Exit' }
        )
        $fixChoice = Show-InteractiveMenu -Items $fixItems -Title 'How would you like to proceed?'

        if ($fixChoice -eq 'PreFlight') {
            Read-VMInfo
            $preFlightOk = Test-Prerequisites
            if (-not $preFlightOk) {
                return $false
            }
            $vmReady = Test-VmReadiness
            if (-not $vmReady) {
                Write-Host ''
                $cont = Show-Confirmation -Prompt 'VM has issues. Continue anyway?' -Default 'No'
                if (-not $cont) { return $false }
            }
            return $true
        }
        return $false
    }

    # ---- Prerequisites passed -- continue with VM verification ----

    # Box-drawing characters
    $tl = [char]0x2554; $tr = [char]0x2557
    $bl = [char]0x255A; $br = [char]0x255D
    $hz = [char]0x2550; $vt = [char]0x2551
    $ml = [char]0x2560; $mr = [char]0x2563

    $cardW = 62
    $innerW = $cardW - 2

    # Collect verification data
    $checks = @{
        AzLogin      = $true
        UserEmail    = $context.Account.Id
        Subscription = $context.Subscription.Name
        SubId        = $context.Subscription.Id
        VmExists     = $null
        VmLocation   = ''
        PowerState   = ''
        OsType       = ''
        RunCommand   = $null  # 'Allowed' / 'Denied' / 'Unknown'
        RoleName     = ''
        ErrorMessage = ''
    }

    # ---- VM exists and status ----
    try {
        $vmBlock = [scriptblock]::Create(@"
            Import-Module Az.Compute -ErrorAction Stop
            `$vm = Get-AzVM -ResourceGroupName '$($script:ResourceGroup -replace "'","''")' ``
                -Name '$($script:VMName -replace "'","''")' -Status -ErrorAction Stop
            `$power = (`$vm.Statuses | Where-Object { `$_.Code -like 'PowerState/*' }).DisplayStatus
            `$detail = Get-AzVM -ResourceGroupName '$($script:ResourceGroup -replace "'","''")' ``
                -Name '$($script:VMName -replace "'","''")' -ErrorAction Stop
            [PSCustomObject]@{
                Location   = `$detail.Location
                OsType     = `$detail.StorageProfile.OsDisk.OsType
                PowerState = `$power
            }
"@)
        $vmInfo = Invoke-WithSpinner -Label 'VM connectivity' -ScriptBlock $vmBlock -TimeoutSeconds 60
        $checks.VmExists = $true
        $checks.VmLocation = $vmInfo.Location
        $checks.OsType = [string]$vmInfo.OsType
        $checks.PowerState = [string]$vmInfo.PowerState
    }
    catch {
        $checks.VmExists = $false
        $checks.ErrorMessage = $_.Exception.Message
        if ($checks.ErrorMessage -match 'not found|could not be found|does not exist') {
            $checks.ErrorMessage = 'VM or resource group not found'
        }
    }

    # ---- RBAC permission check ----
    if ($checks.VmExists) {
        try {
            $rbacBlock = [scriptblock]::Create(@"
                Import-Module Az.Resources -ErrorAction Stop
                `$scope = "/subscriptions/$($checks.SubId)/resourceGroups/$($script:ResourceGroup -replace "'","''")"
                `$assignments = Get-AzRoleAssignment -Scope `$scope -ErrorAction Stop |
                    Where-Object { `$_.SignInName -eq '$($checks.UserEmail -replace "'","''")' -or
                                   `$_.ObjectType -eq 'Unknown' }
                `$runCmdRoles = @('Owner', 'Contributor', 'Virtual Machine Contributor')
                `$match = `$assignments | Where-Object { `$_.RoleDefinitionName -in `$runCmdRoles } | Select-Object -First 1
                if (`$match) {
                    [PSCustomObject]@{ Status = 'Allowed'; Role = `$match.RoleDefinitionName }
                } else {
                    [PSCustomObject]@{ Status = 'Unknown'; Role = '' }
                }
"@)
            $rbacResult = Invoke-WithSpinner -Label 'Permissions (RBAC)' -ScriptBlock $rbacBlock -TimeoutSeconds 30
            $checks.RunCommand = [string]$rbacResult.Status
            $checks.RoleName = [string]$rbacResult.Role
        }
        catch {
            $checks.RunCommand = 'Unknown'
        }
    }

    # ---- Show verification card ----
    Write-Host ''

    if (-not $checks.VmExists) {
        # Failure card
        Write-Host "  $tl$([string]::new($hz, $innerW))$tr" -ForegroundColor Red
        $hdr = '  CONNECTION FAILED'
        $padHdr = $hdr.PadRight($innerW)
        Write-Host "  $vt" -NoNewline -ForegroundColor Red
        Write-Host "$padHdr" -NoNewline -ForegroundColor Red
        Write-Host "$vt" -ForegroundColor Red
        Write-Host "  $bl$([string]::new($hz, $innerW))$br" -ForegroundColor Red
        Write-Host ''
        Write-Host "  [X] $($checks.ErrorMessage)" -ForegroundColor Red
        Write-Host ''
        Write-Host '  Check that the resource group and VM name are correct.' -ForegroundColor Gray
        Write-Host ''

        $retryItems = @(
            @{ Label = 'Re-enter VM details'; Value = 'Retry' }
            @{ Label = 'Exit'; Value = 'Exit' }
        )
        $retryChoice = Show-InteractiveMenu -Items $retryItems -Title ''
        if ($retryChoice -eq 'Retry') {
            $script:ResourceGroup = $null
            $script:VMName = $null
            Read-VMInfo
            return (Test-VMConnection)
        }
        return $false
    }

    # Success card
    $writeRow = {
        param([string]$Label, [string]$Value, [ConsoleColor]$ValueColor = 'White')
        $row = "  $($Label.PadRight(18))$Value"
        $padded = $row.PadRight($innerW)
        if ($padded.Length -gt $innerW) { $padded = $padded.Substring(0, $innerW) }
        Write-Host "  $vt" -NoNewline -ForegroundColor $script:Colors.Border
        Write-Host "$padded" -NoNewline -ForegroundColor $ValueColor
        Write-Host "$vt" -ForegroundColor $script:Colors.Border
    }

    $writeEmpty = {
        Write-Host "  $vt$([string]::new(' ', $innerW))$vt" -ForegroundColor $script:Colors.Border
    }

    # Top border
    Write-Host "  $tl$([string]::new($hz, $innerW))$tr" -ForegroundColor $script:Colors.Border

    # Header
    $hdr = '  CONNECTION VERIFIED'
    $padHdr = $hdr.PadRight($innerW)
    Write-Host "  $vt" -NoNewline -ForegroundColor $script:Colors.Border
    Write-Host "$padHdr" -NoNewline -ForegroundColor Green
    Write-Host "$vt" -ForegroundColor $script:Colors.Border

    # Divider
    Write-Host "  $ml$([string]::new($hz, $innerW))$mr" -ForegroundColor $script:Colors.Border

    & $writeEmpty
    & $writeRow 'VM Name' $script:VMName Cyan
    & $writeRow 'Resource Group' $script:ResourceGroup Cyan
    & $writeRow 'Subscription' $checks.Subscription White
    & $writeRow 'Location' $checks.VmLocation White
    & $writeRow 'OS' $checks.OsType White

    # Power state with color
    $powerColor = if ($checks.PowerState -match 'running') { 'Green' } else { 'Yellow' }
    & $writeRow 'VM Status' $checks.PowerState $powerColor

    & $writeRow 'Signed in as' $checks.UserEmail White

    # RBAC
    $rbacDisplay = switch ($checks.RunCommand) {
        'Allowed' { "Allowed ($($checks.RoleName))" }
        'Denied'  { 'Denied -- needs Contributor or VM Contributor role' }
        default   { 'Not verified (check may require Az.Resources)' }
    }
    $rbacColor = switch ($checks.RunCommand) {
        'Allowed' { 'Green' }
        'Denied'  { 'Red' }
        default   { 'Yellow' }
    }
    & $writeRow 'Run Command' $rbacDisplay $rbacColor

    & $writeEmpty

    # Bottom border
    Write-Host "  $bl$([string]::new($hz, $innerW))$br" -ForegroundColor $script:Colors.Border

    # Warn if VM is not running
    if ($checks.PowerState -and $checks.PowerState -notmatch 'running') {
        Write-Host ''
        Write-Host "  [!] VM is $($checks.PowerState). Simulations require a running VM." -ForegroundColor Yellow
    }

    # Warn if OS is not Windows
    if ($checks.OsType -and $checks.OsType -ne 'Windows') {
        Write-Host ''
        Write-Host "  [!] VM OS is '$($checks.OsType)'. RedTide requires Windows." -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host '  Press Enter to continue...' -ForegroundColor $script:Colors.Muted
    Read-Host | Out-Null

    return $true
}

# ---------------------------------------------------------------------------
# Region: Defender Baseline Capture
# ---------------------------------------------------------------------------

function Save-DefenderBaseline {
    if ($script:LocalMode) {
        Write-Log 'Capturing Defender baseline configuration on local host...'
    }
    else {
        Write-Log 'Capturing Defender baseline configuration on VM...'
    }
    Write-Host ''
    Write-Host '  Snapshots current Defender settings (CFA, ASR rules, Network Protection,' -ForegroundColor DarkGray
    Write-Host '  PUA, Cloud Protection) BEFORE running any strikes, so the Cleanup scenario' -ForegroundColor DarkGray
    if ($script:LocalMode) {
        Write-Host '  can restore this machine to its original state afterward.' -ForegroundColor DarkGray
    }
    else {
        Write-Host '  can restore the VM to its original state afterward.' -ForegroundColor DarkGray
    }
    Write-Host '  Saved to: C:\MDE-Demo\baseline-state.json' -ForegroundColor DarkGray
    Write-Host ''

    # Inner baseline-capture script (runs on the target host -- local or remote VM)
    $baselineInnerScript = @'
        New-Item -ItemType Directory -Path 'C:\MDE-Demo' -Force | Out-Null
        $prefs = Get-MpPreference

        # Capture policy-level registry values (Intune/GPO overrides)
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
        $cfaPolicy = $null
        if (Test-Path $policyPath) {
            $cfaPolicy = (Get-ItemProperty $policyPath -Name EnableControlledFolderAccess -ErrorAction SilentlyContinue).EnableControlledFolderAccess
        }

        $state = @{
            CFA              = $prefs.EnableControlledFolderAccess
            CFA_Policy       = $cfaPolicy
            NetworkProtection = $prefs.EnableNetworkProtection
            PUAProtection    = $prefs.PUAProtection
            MAPSReporting    = $prefs.MAPSReporting
            SubmitSamples    = $prefs.SubmitSamplesConsent
            BehaviorMonitoring = $prefs.DisableBehaviorMonitoring
            CFAFolders       = @($prefs.ControlledFolderAccessProtectedFolders)
            ASR_Ids          = @($prefs.AttackSurfaceReductionRules_Ids)
            ASR_Actions      = @($prefs.AttackSurfaceReductionRules_Actions)
        }
        $state | ConvertTo-Json -Depth 5 | Out-File 'C:\MDE-Demo\baseline-state.json' -Encoding utf8
        Write-Output "Baseline saved"
'@

    try {
        if ($script:LocalMode) {
            # ----- Local mode: run baseline capture directly in a background job -----
            $baselineBlock = [scriptblock]::Create(@"
                `$sb = [scriptblock]::Create(@'
$baselineInnerScript
'@)
                & `$sb
"@)
            $output = Invoke-WithSpinner -Label 'Saving Defender baseline (local)' -ScriptBlock $baselineBlock -TimeoutSeconds 120
        }
        else {
            # ----- Azure mode: ship baseline capture via Invoke-AzVMRunCommand -----
            $baselineBlock = [scriptblock]::Create(@"
                Import-Module Az.Compute -ErrorAction Stop
                `$r = Invoke-AzVMRunCommand ``
                    -ResourceGroupName '$($script:ResourceGroup -replace "'","''")' ``
                    -VMName '$($script:VMName -replace "'","''")' ``
                    -CommandId 'RunPowerShellScript' ``
                    -ScriptString @'
$baselineInnerScript
'@ ``
                    -ErrorAction Stop
                (`$r.Value | Where-Object { `$_.Code -eq 'ComponentStatus/StdOut/succeeded' }).Message
"@)
            $output = Invoke-WithSpinner -Label 'Saving Defender baseline (Run Command to VM)' -ScriptBlock $baselineBlock -TimeoutSeconds 120
        }

        if ($output -match 'Baseline saved') {
            Write-Log 'Defender baseline captured and saved to C:\MDE-Demo\baseline-state.json' -Level SUCCESS
            $script:BaselineCaptured = $true
            return $true
        }
        else {
            Write-Log 'Baseline capture returned unexpected output.' -Level WARN
            Write-Log 'Cleanup will reset settings to Windows defaults instead of original values.' -Level WARN
            return $false
        }
    }
    catch {
        Write-Log "Could not capture baseline: $_" -Level WARN
        Write-Log 'Cleanup will reset settings to Windows defaults instead of original values.' -Level WARN
        return $false
    }
}

# ---------------------------------------------------------------------------
# Region: Local Mode Pre-flight + Connection
# ---------------------------------------------------------------------------

function Test-IsLocalAdmin {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-LocalPrerequisites {
    Show-PageBanner -Title 'Local Pre-flight Checks' -Color Cyan
    Write-Log 'Running local pre-flight checks...'

    $issues = @()

    # 1. Operating system
    $isWin = ($env:OS -eq 'Windows_NT')
    if ($isWin) {
        Write-CheckResult -Label 'Operating system' -Status 'pass' -Detail 'Windows'
    }
    else {
        Write-CheckResult -Label 'Operating system' -Status 'fail' -Detail "Not Windows ($env:OS)"
        $issues += 'RedTide requires Windows. Detected: ' + $env:OS
    }

    # 2. PowerShell version
    $psVer = $PSVersionTable.PSVersion
    if ($psVer.Major -ge 5) {
        Write-CheckResult -Label 'PowerShell version' -Status 'pass' -Detail "$psVer"
    }
    else {
        Write-CheckResult -Label 'PowerShell version' -Status 'fail' -Detail "$psVer (need 5.1+)"
        $issues += 'PowerShell 5.1 or later required.'
    }

    # 3. 64-bit process (32-bit PowerShell would silently hit registry redirection
    #    when writing HKLM Defender policy keys -- cleanup/restore would not work).
    if ([Environment]::Is64BitProcess) {
        Write-CheckResult -Label 'PowerShell architecture' -Status 'pass' -Detail '64-bit'
    }
    else {
        Write-CheckResult -Label 'PowerShell architecture' -Status 'fail' -Detail '32-bit (need 64-bit)'
        $issues += 'Run RedTide from 64-bit Windows PowerShell. 32-bit hits HKLM registry redirection.'
    }

    # 4. Administrator privileges
    $isAdmin = Test-IsLocalAdmin
    if ($isAdmin) {
        Write-CheckResult -Label 'Administrator privileges' -Status 'pass' -Detail 'Elevated'
    }
    else {
        Write-CheckResult -Label 'Administrator privileges' -Status 'fail' -Detail 'Not elevated'
        $issues += 'Run PowerShell as Administrator. Set-MpPreference and HKLM policy writes require elevation.'
    }

    # 5. Defender Antivirus present + running
    $mpStatus = $null
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        Write-CheckResult -Label 'Microsoft Defender Antivirus' -Status 'fail' -Detail 'Get-MpComputerStatus failed'
        $issues += 'Get-MpComputerStatus failed. A third-party AV may have disabled Defender.'
    }
    if ($mpStatus) {
        if ($mpStatus.AMServiceEnabled) {
            if ($mpStatus.RealTimeProtectionEnabled) {
                Write-CheckResult -Label 'Microsoft Defender Antivirus' -Status 'pass' -Detail 'Active, RTP on'
            }
            else {
                Write-CheckResult -Label 'Microsoft Defender Antivirus' -Status 'warn' -Detail 'Active, RTP OFF'
                Write-Log 'Real-Time Protection is OFF. Most detection scenarios will not trigger.' -Level WARN
            }
        }
        else {
            Write-CheckResult -Label 'Microsoft Defender Antivirus' -Status 'fail' -Detail 'Service disabled'
            $issues += 'Defender AV service is disabled.'
        }
    }

    # 6. MDE Sense service (warn only -- AV-only demos still work without it)
    $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
    if ($sense -and $sense.Status -eq 'Running') {
        Write-CheckResult -Label 'Defender for Endpoint sensor' -Status 'pass' -Detail 'Onboarded (Sense running)'
    }
    elseif ($sense) {
        Write-CheckResult -Label 'Defender for Endpoint sensor' -Status 'warn' -Detail "Sense $($sense.Status)"
        Write-Log 'Sense service is not running. EDR Detection scenario will not fire portal alerts.' -Level WARN
    }
    else {
        Write-CheckResult -Label 'Defender for Endpoint sensor' -Status 'warn' -Detail 'Not onboarded'
        Write-Log 'Host is not onboarded to MDE. EDR Detection scenario will not fire portal alerts.' -Level WARN
    }

    if ($issues.Count -gt 0) {
        Write-Host ''
        Write-Host '  MISSING REQUIREMENTS' -ForegroundColor $script:Colors.Warning
        Write-Host "  $([string]::new([char]0x2500, 40))" -ForegroundColor $script:Colors.Warning
        Write-Host ''
        foreach ($issue in $issues) {
            Write-Host "    - $issue" -ForegroundColor Gray
        }
        Write-Host ''
        return $false
    }

    Write-Log 'All local pre-flight checks passed.' -Level SUCCESS
    return $true
}

function Test-LocalConnection {
    Show-PageBanner -Title 'Local Mode' -Color Cyan
    Write-Log 'Verifying local environment...'

    # Gather info
    $hostname = $env:COMPUTERNAME
    $userName = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
    $osVer = $null
    try {
        $osVer = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
    }
    catch {
        $osVer = 'Windows'
    }

    $isAdmin = Test-IsLocalAdmin

    $mpStatus = $null
    try { $mpStatus = Get-MpComputerStatus -ErrorAction Stop } catch {}

    $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue

    # ---- Show verification card ----
    $tl = [char]0x2554; $tr = [char]0x2557
    $bl = [char]0x255A; $br = [char]0x255D
    $hz = [char]0x2550; $vt = [char]0x2551
    $ml = [char]0x2560; $mr = [char]0x2563
    $cardW = 62
    $innerW = $cardW - 2

    $writeRow = {
        param([string]$Label, [string]$Value, [ConsoleColor]$ValueColor = 'White')
        $row = "  $($Label.PadRight(20))$Value"
        $padded = $row.PadRight($innerW)
        if ($padded.Length -gt $innerW) { $padded = $padded.Substring(0, $innerW) }
        Write-Host "  $vt" -NoNewline -ForegroundColor $script:Colors.Border
        Write-Host "$padded" -NoNewline -ForegroundColor $ValueColor
        Write-Host "$vt" -ForegroundColor $script:Colors.Border
    }
    $writeEmpty = {
        Write-Host "  $vt$([string]::new(' ', $innerW))$vt" -ForegroundColor $script:Colors.Border
    }

    Write-Host ''
    Write-Host "  $tl$([string]::new($hz, $innerW))$tr" -ForegroundColor $script:Colors.Border

    $hdr = '  LOCAL MODE -- RUNS ON THIS MACHINE'
    $padHdr = $hdr.PadRight($innerW)
    if ($padHdr.Length -gt $innerW) { $padHdr = $padHdr.Substring(0, $innerW) }
    Write-Host "  $vt" -NoNewline -ForegroundColor $script:Colors.Border
    Write-Host "$padHdr" -NoNewline -ForegroundColor Yellow
    Write-Host "$vt" -ForegroundColor $script:Colors.Border

    Write-Host "  $ml$([string]::new($hz, $innerW))$mr" -ForegroundColor $script:Colors.Border

    & $writeEmpty
    & $writeRow 'Hostname' $hostname Cyan
    & $writeRow 'Operating system' $osVer White
    & $writeRow 'Signed in as' $userName White

    $elevDisplay = if ($isAdmin) { 'Administrator' } else { 'NOT ADMIN' }
    $elevColor = if ($isAdmin) { 'Green' } else { 'Red' }
    & $writeRow 'Elevation' $elevDisplay $elevColor

    if ($mpStatus) {
        $avDisplay = if ($mpStatus.AMServiceEnabled) { 'Active' } else { 'Disabled' }
        $avColor = if ($mpStatus.AMServiceEnabled) { 'Green' } else { 'Red' }
        & $writeRow 'Defender AV' $avDisplay $avColor

        $rtDisplay = if ($mpStatus.RealTimeProtectionEnabled) { 'On' } else { 'OFF' }
        $rtColor = if ($mpStatus.RealTimeProtectionEnabled) { 'Green' } else { 'Yellow' }
        & $writeRow 'Real-time protection' $rtDisplay $rtColor
    }
    else {
        & $writeRow 'Defender AV' 'Unknown (cmdlet failed)' 'Yellow'
    }

    if ($sense -and $sense.Status -eq 'Running') {
        & $writeRow 'MDE sensor (Sense)' 'Running (onboarded)' 'Green'
    }
    elseif ($sense) {
        & $writeRow 'MDE sensor (Sense)' "$($sense.Status)" 'Yellow'
    }
    else {
        & $writeRow 'MDE sensor (Sense)' 'Not onboarded' 'Yellow'
    }

    & $writeEmpty
    Write-Host "  $bl$([string]::new($hz, $innerW))$br" -ForegroundColor $script:Colors.Border

    Write-Host ''
    Write-Host '  [!] WARNING: Simulations will run on THIS machine.' -ForegroundColor Yellow
    Write-Host '      Defender settings (CFA, ASR, Network Protection, PUA, Exploit Protection)' -ForegroundColor Gray
    Write-Host '      will be modified. EICAR / AMSI / PUA test files will be quarantined here.' -ForegroundColor Gray
    Write-Host '      Use the Cleanup scenario to restore your original configuration.' -ForegroundColor Gray
    Write-Host ''

    if (-not $isAdmin) {
        Write-Host '  [X] You are not running as Administrator.' -ForegroundColor Red
        Write-Host '      Most simulations will fail. Re-launch PowerShell as Administrator.' -ForegroundColor Gray
        Write-Host ''
        return $false
    }

    Write-Host '  Press Enter to continue...' -ForegroundColor $script:Colors.Muted
    Read-Host | Out-Null
    return $true
}

# ---------------------------------------------------------------------------
# Region: Scenario Dispatching
# ---------------------------------------------------------------------------

function Show-ScenarioBriefing {
    param([string]$ScenarioName)

    # Scenario briefing data sourced from Microsoft Learn demonstration guides
    # plus VM-specific details from strike module analysis
    $briefings = @{
        'CloudProtection' = @{
            Area        = 'Next Generation Protection'
            What        = 'Downloads a test file that has no local signature. When the file is accessed, Defender sends its metadata to cloud ML models. Within seconds the cloud verdict comes back as malicious -- the file is blocked and deleted before it can execute.'
            Alert       = '''Presenoker'' unwanted software was prevented'
            WaitTime    = '1-2 minutes'
            VmFolder    = 'C:\MDE-Demo'
            VmFiles     = 'cloud-test-file.zip (from go.microsoft.com)'
            VmConfig    = 'Enables MAPSReporting Advanced + SubmitSamplesConsent'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-cloud-delivered-protection'
            ManualSteps = 'RDP into VM > open C:\MDE-Demo > extract cloud-test-file.zip (password: infected) > double-click the extracted file'
        }
        'Amsi' = @{
            Area        = 'Next Generation Protection'
            What        = 'Tests AMSI across three script engines: PowerShell, VBScript, and JavaScript. Each script contains the AMSI test GUID. When the script engine executes, it passes the code to AMSI, which forwards it to Defender. Defender recognizes the pattern and blocks execution -- even if obfuscated.'
            Alert       = '''MpTest'' malware was prevented + ''Wacatac'' (JS file quarantined)'
            WaitTime    = '1-5 minutes'
            VmFolder    = 'C:\MDE-Demo'
            VmFiles     = 'AMSI_test.ps1, AMSI_test.vbs, AMSI_test.js'
            VmConfig    = 'Verifies RTP and Behavior Monitoring are enabled'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/mde-demonstration-amsi'
        }
        'AntivirusValidation' = @{
            Area        = 'Next Generation Protection'
            What        = 'Writes the industry-standard EICAR test string to a file. EICAR is a 68-byte string every AV engine recognizes as a test threat. Defender real-time protection detects it instantly, quarantines the file, and reports to the portal. Validates: device onboarded, AV active, threat reporting works.'
            Alert       = '''EICAR_Test_File'' malware was prevented'
            WaitTime    = '1-2 minutes'
            VmFolder    = 'C:\MDE-Demo'
            VmFiles     = 'EICAR-test.txt (quarantined on creation)'
            VmConfig    = 'Verifies AV service running and RTP enabled'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/validate-antimalware'
        }
        'BehaviorMonitoring' = @{
            Area        = 'Next Generation Protection'
            What        = 'Runs a command where PowerShell spawns another PowerShell with suspicious arguments. The command fails (expected), but Defender behavior monitoring watches runtime process patterns, not file signatures. It flags the suspicious parent-child process relationship.'
            Alert       = 'Suspicious ''BmTestOfflineUI'' behavior was blocked'
            WaitTime    = '2-5 minutes'
            VmFolder    = 'C:\MDE-Demo'
            VmFiles     = 'None (process-based test)'
            VmConfig    = 'Enables MAPSReporting Advanced if disabled'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/demonstration-behavior-monitoring'
        }
        'Pua' = @{
            Area        = 'Next Generation Protection'
            What        = 'Enables PUA protection and attempts to download the AMTSO PUA test file. Defender identifies it as a Potentially Unwanted Application and blocks the download. PUA catches adware, bundlers, and browser toolbars that degrade user experience.'
            Alert       = '''EICAR_Test_File'' unwanted software was prevented'
            WaitTime    = '1-5 minutes'
            VmFolder    = 'C:\MDE-Demo'
            VmFiles     = 'PotentiallyUnwanted.exe (blocked on download)'
            VmConfig    = 'Set-MpPreference -PUAProtection Enabled'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-potentially-unwanted-applications'
            ManualSteps = 'RDP into VM > open Edge > go to amtso.org/feature-settings-check-potentially-unwanted-applications > click the PUA test download link'
        }
        'AppReputation' = @{
            Area        = 'Next Generation Protection'
            What        = 'Tests SmartScreen app reputation in Edge. Uses three test downloads from Microsoft: a known-safe file (downloads normally), an unknown file (SmartScreen warns), and a known-malicious file (SmartScreen blocks AND Defender AV quarantines as Trojan:Win32/Demo). Two layers of protection in one demo.'
            Alert       = '''Demo'' malware was prevented (from Known Malware test)'
            WaitTime    = '1-2 minutes (Known Malware test generates alert)'
            VmFolder    = 'No files created on VM'
            VmFiles     = 'Requires RDP + Microsoft Edge'
            VmConfig    = 'Verifies Defender AV health'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-app-reputation'
            ManualSteps = 'RDP into VM > open Edge > go to https://demo.smartscreen.msft.net > scroll to "App Rep Demos" > (1) Known Good: download + run = runs with "established reputation" message > (2) Unknown: download + run = SmartScreen warns "not commonly downloaded" > (3) Known Malware: download + run = "blocked as unsafe by Microsoft Defender SmartScreen"'
        }
        'UrlReputation' = @{
            Area        = 'Next Generation Protection'
            What        = 'Tests SmartScreen URL reputation in Edge. Navigates to test URLs for phishing, malware, exploits, and malvertising. Suspicious sites show a warning, known threats show a full red block page.'
            Alert       = 'SmartScreen URL block (red block page)'
            WaitTime    = 'Immediate (browser-level)'
            VmFolder    = 'No files created on VM'
            VmFiles     = 'Requires RDP + Microsoft Edge (6 test URLs)'
            VmConfig    = 'Verifies Edge is installed'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-smartscreen-url-reputation'
            ManualSteps = 'RDP into VM > open Edge > go to https://demo.smartscreen.msft.net > use the "URL Rep Demos" section > test phishing, malware, blocked download, exploit, and malvertising links'
        }
        'ControlledFolder' = @{
            Area        = 'Attack Surface Reduction'
            What        = 'Creates C:\demo with sample business documents, enables CFA, downloads the ransomware test executable, and runs it. The test file tries to encrypt C:\demo (hardcoded target). CFA blocks every write attempt. The files remain intact.'
            Alert       = 'ControlledFolderAccessViolationBlocked (Advanced Hunting / Device Timeline)'
            WaitTime    = '1-2 minutes (check Advanced Hunting, not Incidents)'
            VmFolder    = 'C:\demo'
            VmFiles     = 'Q4-Financial-Report.txt, Employee-Records.txt, Board-Meeting-Notes.txt'
            VmConfig    = 'Enables CFA + protects C:\demo, test exe in C:\MDE-Demo'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-controlled-folder-access'
        }
        'AsrRules' = @{
            Area        = 'Attack Surface Reduction'
            What        = 'Enables 9 ASR rules in Block mode. Deploys a .docm test document with a VBA macro to C:\MDE-Demo\asr-tests and a one-click launcher (Run-AsrTest.bat). When you double-click the launcher via RDP, it configures Office trust and opens the document. ASR blocks Word from spawning cmd.exe.'
            Alert       = 'AsrOfficeChildProcessBlocked (Advanced Hunting)'
            WaitTime    = '1-10 minutes for events to appear in Advanced Hunting'
            VmFolder    = 'C:\MDE-Demo\asr-tests'
            VmFiles     = 'Run-AsrTest.bat (one-click helper that creates .docm and opens Word)'
            VmConfig    = 'Enables 9 ASR rules via preference + policy registry (handles Intune override)'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules'
            ManualSteps = 'RDP into VM > double-click C:\MDE-Demo\asr-tests\Run-AsrTest.bat > Word opens and shows VBA "Runtime Error 5: Invalid procedure call" -- this IS expected, it proves ASR blocked cmd.exe > click OK to dismiss > press Enter here to continue for KQL verification'
        }
        'CfaTestTool' = @{
            Area        = 'Attack Surface Reduction'
            What        = 'Enables CFA and downloads Microsoft''s CFA test tool (CFAtool.exe). When you launch the GUI tool and attempt to write to a protected folder, CFA blocks the write because CFAtool is not trusted. Simulates untrusted software modifying protected files.'
            Alert       = 'ControlledFolderAccessViolationBlocked (Advanced Hunting, not alerts queue)'
            WaitTime    = '1-2 minutes'
            VmFolder    = 'C:\MDE-Demo'
            VmFiles     = 'CFAtool.exe (GUI, from demo.wd.microsoft.com)'
            VmConfig    = 'Set-MpPreference -EnableControlledFolderAccess Enabled'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-controlled-folder-access-test-tool'
            ManualSteps = 'RDP into VM > navigate to C:\MDE-Demo > double-click CFAtool.exe > in the tool, browse to C:\Users\<username>\Documents (a default protected folder) > click the Write button -- CFA blocks the write'
        }
        'ExploitProtection' = @{
            Area        = 'Attack Surface Reduction'
            What        = 'Downloads and applies a Microsoft Exploit Protection XML policy enabling system-wide mitigations: DEP, ASLR, CFG, and SEHOP. These block entire classes of memory-based exploits. Configuration demo -- no alert is generated.'
            Alert       = 'No alert (configuration only)'
            WaitTime    = 'No wait needed -- verify settings via RDP'
            VmFolder    = 'C:\MDE-Demo'
            VmFiles     = 'ProcessMitigation.xml (policy), EP-backup.xml (backup)'
            VmConfig    = 'Set-ProcessMitigation -PolicyFilePath (DEP/ASLR/CFG/SEHOP)'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-exploit-protection'
            ManualSteps = 'RDP into VM > open Windows Security > App and Browser Control > Exploit Protection > review System settings to confirm DEP, ASLR, CFG, SEHOP are enabled'
        }
        'NetworkProtection' = @{
            Area        = 'Attack Surface Reduction'
            What        = 'Enables Network Protection, which works at the network layer across ALL apps (not just Edge). Navigates to smartscreentestratings2.net. Network Protection intercepts and blocks the connection. The browser shows a connection error -- proving network-layer blocking.'
            Alert       = 'Network Protection blocked a dangerous domain'
            WaitTime    = '1-5 minutes'
            VmFolder    = 'C:\MDE-Demo'
            VmFiles     = 'None (network-layer test)'
            VmConfig    = 'Set-MpPreference -EnableNetworkProtection Enabled'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-network-protection'
            ManualSteps = 'RDP into VM > open Chrome or Firefox (NOT Edge) > navigate to https://smartscreentestratings2.net'
        }
        'EdrDetection' = @{
            Area        = 'Endpoint Detection and Response'
            What        = 'Creates a suspicious process chain: cmd.exe spawns powershell.exe with download-and-execute arguments targeting localhost. The download fails (expected), but EDR flags the suspicious behavior pattern matching known attack techniques. Triggers a test alert with full process tree.'
            Alert       = 'Suspicious PowerShell command line'
            WaitTime    = '2-10 minutes'
            VmFolder    = 'C:\MDE-Demo\edr-test'
            VmFiles     = 'invoice.exe (download attempt to localhost, fails)'
            VmConfig    = 'Verifies MDE sensor (Sense service) is running'
            LearnMore   = 'https://learn.microsoft.com/en-us/defender-endpoint/edr-detection'
        }
    }

    $info = $briefings[$ScenarioName]
    if (-not $info) { return }

    # Box-drawing characters
    $tl = [char]0x2554; $tr = [char]0x2557  # ╔ ╗
    $bl = [char]0x255A; $br = [char]0x255D  # ╚ ╝
    $hz = [char]0x2550; $vt = [char]0x2551  # ═ ║
    $ml = [char]0x2560; $mr = [char]0x2563  # ╠ ╣
    $th = [char]0x2500                      # ─

    # Card width adapts to terminal (min 62, max terminal - 4 for side margins)
    $termW = try { [Console]::WindowWidth } catch { 80 }
    $cardW = [Math]::Max(62, [Math]::Min($termW - 4, 100))
    $innerW = $cardW - 2  # space inside ║...║

    # Helper: write one or more lines inside the card frame, wrapping if needed
    $writeLine = {
        param([string]$Text, [ConsoleColor]$TextColor = 'Gray')
        $contentW = $innerW - 2  # 2 chars for leading indent inside frame
        # If text fits, write it directly; otherwise wrap
        $segments = @()
        if ($Text.Length -le $contentW) {
            $segments = @($Text)
        } else {
            # Word-wrap with hard break for long tokens
            $words = $Text -split '\s+'
            $line = ''
            foreach ($w in $words) {
                while ($w.Length -gt $contentW) {
                    if ($line) { $segments += $line; $line = '' }
                    $segments += $w.Substring(0, $contentW)
                    $w = $w.Substring($contentW)
                }
                if (-not $w) { continue }
                if (($line.Length + $w.Length + 1) -gt $contentW) {
                    $segments += $line
                    $line = $w
                } else {
                    if ($line) { $line += " $w" } else { $line = $w }
                }
            }
            if ($line) { $segments += $line }
        }
        foreach ($seg in $segments) {
            $padded = "  $seg".PadRight($innerW)
            if ($padded.Length -gt $innerW) { $padded = $padded.Substring(0, $innerW) }
            Write-Host -NoNewline "  $vt" -ForegroundColor $script:Colors.Border
            Write-Host -NoNewline $padded -ForegroundColor $TextColor
            Write-Host "$vt" -ForegroundColor $script:Colors.Border
        }
    }
    $writeEmpty = { & $writeLine -Text '' }
    $writeLabel = { param([string]$L) & $writeLine -Text $L -TextColor White }
    $writeValue = { param([string]$V) & $writeLine -Text $V -TextColor Cyan }
    $writeMuted = { param([string]$V) & $writeLine -Text $V -TextColor DarkGray }
    $writeBody  = { param([string]$V) & $writeLine -Text $V -TextColor Gray }

    # Word-wrap text into lines that fit inside the card
    $wrapText = {
        param([string]$Text, [int]$MaxLen)
        $words = $Text -split '\s+'
        $lines = @()
        $line = ''
        foreach ($word in $words) {
            # Break words longer than MaxLen into chunks
            while ($word.Length -gt $MaxLen) {
                if ($line) { $lines += $line; $line = '' }
                $lines += $word.Substring(0, $MaxLen)
                $word = $word.Substring($MaxLen)
            }
            if (-not $word) { continue }
            if (($line.Length + $word.Length + 1) -gt $MaxLen) {
                $lines += $line
                $line = $word
            } else {
                if ($line) { $line += " $word" } else { $line = $word }
            }
        }
        if ($line) { $lines += $line }
        $lines
    }

    # Card header
    $headerLeft = 'SCENARIO BRIEFING'
    $headerRight = $info.Area
    $headerPad = $innerW - $headerLeft.Length - $headerRight.Length - 4
    if ($headerPad -lt 1) { $headerPad = 1 }
    $headerText = "  $headerLeft$([string]::new(' ', $headerPad))$headerRight"

    Write-Host ''
    Write-Host "  $tl$([string]::new($hz, $innerW))$tr" -ForegroundColor $script:Colors.Border
    $headerPadded = $headerText.PadRight($innerW)
    if ($headerPadded.Length -gt $innerW) { $headerPadded = $headerPadded.Substring(0, $innerW) }
    Write-Host -NoNewline "  $vt" -ForegroundColor $script:Colors.Border
    Write-Host -NoNewline $headerPadded -ForegroundColor $script:Colors.Title
    Write-Host "$vt" -ForegroundColor $script:Colors.Border
    Write-Host "  $ml$([string]::new($th, $innerW))$mr" -ForegroundColor $script:Colors.Border

    # WHAT HAPPENS
    & $writeEmpty
    & $writeLabel 'WHAT HAPPENS'
    $descLines = & $wrapText -Text $info.What -MaxLen ($innerW - 4)
    foreach ($dl in $descLines) { & $writeBody $dl }

    # ON THE VM
    & $writeEmpty
    & $writeLabel 'ON THE VM'
    & $writeValue "Folder:     $($info.VmFolder)"
    & $writeValue "Files:      $($info.VmFiles)"
    & $writeMuted "Configures: $($info.VmConfig)"

    # EXPECTED ALERT + WAIT TIME
    & $writeEmpty
    & $writeLabel 'EXPECTED ALERT'
    & $writeValue $info.Alert
    & $writeMuted "Wait: $($info.WaitTime)"

    # MANUAL STEPS (only for partially automated scenarios)
    if ($info.ContainsKey('ManualSteps') -and $info.ManualSteps) {
        & $writeEmpty
        & $writeLabel 'ACTION REQUIRED AFTER DEPLOYMENT'
        $stepLines = & $wrapText -Text $info.ManualSteps -MaxLen ($innerW - 4)
        foreach ($sl in $stepLines) { & $writeLine -Text $sl -TextColor Yellow }
    }

    # Card bottom
    & $writeEmpty
    Write-Host "  $bl$([string]::new($hz, $innerW))$br" -ForegroundColor $script:Colors.Border

    # Learn More (outside card so URL is never broken/wrapped)
    Write-Host ''
    Write-Host "  Learn more: $($info.LearnMore)" -ForegroundColor DarkGray
    Write-Host ''
}

function Invoke-Scenario {
    param(
        [Parameter(Mandatory)]
        [string]$ScenarioName
    )

    if ($ScenarioName -eq 'All') {
        Show-PageBanner -Title 'Deploy All Strikes' -Color Magenta -NoClear
        Write-Log 'Deploying all attack simulations in sequence...'

        $scenarios = @(
            'CloudProtection', 'Amsi', 'AntivirusValidation', 'BehaviorMonitoring',
            'Pua', 'AppReputation', 'UrlReputation',
            'ControlledFolder', 'AsrRules', 'CfaTestTool', 'ExploitProtection', 'NetworkProtection',
            'EdrDetection'
        )
        $failed = @()

        $total = $scenarios.Count
        $completed = 0

        foreach ($s in $scenarios) {
            $completed++
            Write-Host "  [$completed/$total] " -NoNewline -ForegroundColor $script:Colors.Muted
            $result = Invoke-Scenario -ScenarioName $s
            if ($result -eq $false) {
                $failed += $s
                Write-Log "Scenario '$s' failed. Continuing with next..." -Level WARN
            }
        }

        Write-Host ''
        if ($failed.Count -gt 0) {
            Write-Log "$($total - $failed.Count)/$total simulations succeeded." -Level WARN
            Write-Log "Failed: $($failed -join ', ')" -Level ERROR
            return $false
        }
        Write-Log "All $total simulations deployed successfully." -Level SUCCESS
        return $true
    }

    $modulesDir = Join-Path $PSScriptRoot 'redtide-modules'

    switch ($ScenarioName) {
        'CloudProtection' {
            $modulePath = Join-Path $modulesDir 'Deploy-CloudProtectionStrike.ps1'
            Show-PageBanner -Title 'Cloud-Delivered Protection' -Color Blue
        }
        'Amsi' {
            $modulePath = Join-Path $modulesDir 'Deploy-AmsiStrike.ps1'
            Show-PageBanner -Title 'AMSI Script Detection' -Color Blue
        }
        'AntivirusValidation' {
            $modulePath = Join-Path $modulesDir 'Deploy-AntivirusValidationStrike.ps1'
            Show-PageBanner -Title 'Antivirus Validation' -Color Blue
        }
        'BehaviorMonitoring' {
            $modulePath = Join-Path $modulesDir 'Deploy-BehaviorMonitoringStrike.ps1'
            Show-PageBanner -Title 'Behavior Monitoring' -Color Blue
        }
        'Pua' {
            $modulePath = Join-Path $modulesDir 'Deploy-PuaStrike.ps1'
            Show-PageBanner -Title 'PUA Detection' -Color Blue
        }
        'AppReputation' {
            $modulePath = Join-Path $modulesDir 'Deploy-AppReputationStrike.ps1'
            Show-PageBanner -Title 'App Reputation' -Color Blue
        }
        'UrlReputation' {
            $modulePath = Join-Path $modulesDir 'Deploy-UrlReputationStrike.ps1'
            Show-PageBanner -Title 'URL Reputation' -Color Blue
        }
        'ControlledFolder' {
            $modulePath = Join-Path $modulesDir 'Deploy-ControlledFolderStrike.ps1'
            Show-PageBanner -Title 'Controlled Folder Access' -Color DarkCyan
        }
        'AsrRules' {
            $modulePath = Join-Path $modulesDir 'Deploy-AsrRulesStrike.ps1'
            Show-PageBanner -Title 'ASR Rules' -Color DarkCyan
        }
        'CfaTestTool' {
            $modulePath = Join-Path $modulesDir 'Deploy-CfaTestToolStrike.ps1'
            Show-PageBanner -Title 'CFA Test Tool' -Color DarkCyan
        }
        'ExploitProtection' {
            $modulePath = Join-Path $modulesDir 'Deploy-ExploitProtectionStrike.ps1'
            Show-PageBanner -Title 'Exploit Protection' -Color DarkCyan
        }
        'NetworkProtection' {
            $modulePath = Join-Path $modulesDir 'Deploy-NetworkProtectionStrike.ps1'
            Show-PageBanner -Title 'Network Protection' -Color DarkCyan
        }
        'EdrDetection' {
            $modulePath = Join-Path $modulesDir 'Deploy-EdrDetectionStrike.ps1'
            Show-PageBanner -Title 'EDR Detection Test' -Color Magenta
        }
        'Cleanup' {
            $modulePath = Join-Path $modulesDir 'Remove-AllStrikes.ps1'
            Show-PageBanner -Title 'Cleanup' -Color Yellow
        }
    }

    # Show scenario briefing (what this test does, expected alert, wait time)
    Show-ScenarioBriefing -ScenarioName $ScenarioName

    if (-not (Test-Path $modulePath)) {
        Write-Log "Module not found: $modulePath" -Level ERROR
        return $false
    }

    Write-Log "Loading module: $modulePath"
    . $modulePath

    $functionName = switch ($ScenarioName) {
        'CloudProtection'      { 'Deploy-CloudProtectionStrike' }
        'Amsi'                 { 'Deploy-AmsiStrike' }
        'AntivirusValidation'  { 'Deploy-AntivirusValidationStrike' }
        'BehaviorMonitoring'   { 'Deploy-BehaviorMonitoringStrike' }
        'Pua'                  { 'Deploy-PuaStrike' }
        'AppReputation'        { 'Deploy-AppReputationStrike' }
        'UrlReputation'        { 'Deploy-UrlReputationStrike' }
        'ControlledFolder'     { 'Deploy-ControlledFolderStrike' }
        'AsrRules'             { 'Deploy-AsrRulesStrike' }
        'CfaTestTool'          { 'Deploy-CfaTestToolStrike' }
        'ExploitProtection'    { 'Deploy-ExploitProtectionStrike' }
        'NetworkProtection'    { 'Deploy-NetworkProtectionStrike' }
        'EdrDetection'         { 'Deploy-EdrDetectionStrike' }
        'Cleanup'              { 'Remove-AllStrikes' }
    }

    try {
        $moduleResult = & $functionName
        if ($moduleResult -eq $false) {
            return $false
        }
        return $true
    }
    catch {
        Write-Log "Scenario failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Show-NextSteps {
    param(
        [string]$ScenarioName,
        [bool]$Success = $true
    )

    $portalUrl = 'https://security.microsoft.com'

    # ---- Alert explanation data per scenario ----
    $alertInfo = @{
        'CloudProtection' = @{
            AlertName   = '''Presenoker'' unwanted software was prevented'
            HowItWorks  = 'The script downloads a test file from Microsoft (https://go.microsoft.com/fwlink/?linkid=2298135). This file has no local signature -- it is unknown to the device. When the file is accessed, Defender sends its metadata to seven cloud ML models. Within seconds, the cloud verdict comes back as malicious and the file is blocked and deleted.'
            ProcessChain = 'Explorer.exe > test file (blocked by cloud verdict before execution)'
            PortalPath  = "$portalUrl/alerts"
            WaitTime    = '1-2 minutes'
            ManualSteps = 'RDP into VM > open C:\MDE-Demo > extract cloud-test-file.zip (password: infected) > double-click the extracted file'
        }
        'Amsi' = @{
            AlertName   = '''MpTest'' malware was prevented + ''Wacatac'' (JS file quarantined)'
            HowItWorks  = 'The script creates test files containing the AMSI test GUID (7e72c3ce-861b-4339-8740-0ac1484c1386) in PowerShell, VBScript, and JScript formats. When each script engine attempts to execute, it passes the code to AMSI, which forwards it to Defender. Defender recognizes the test pattern and blocks execution before any code runs -- even if the script was obfuscated.'
            ProcessChain = 'powershell.exe > AMSI_test.ps1 (blocked) | cscript.exe > AMSI_test.vbs (blocked) | cscript.exe > AMSI_test.js (blocked)'
            PortalPath  = "$portalUrl/alerts"
            WaitTime    = '1-5 minutes'
        }
        'AntivirusValidation' = @{
            AlertName   = '''EICAR_Test_File'' malware was prevented'
            HowItWorks  = 'The script writes the industry-standard EICAR test string to a file. EICAR is a 68-byte string that every antivirus engine recognizes as a test threat. The moment the file is written, Defender real-time protection detects it, quarantines the file, and reports it to the portal. This validates three things: the device is onboarded, AV is active, and threat reporting flows correctly.'
            ProcessChain = 'powershell.exe > WriteAllText > EICAR-test.txt (quarantined immediately)'
            PortalPath  = "$portalUrl/alerts"
            WaitTime    = '1-2 minutes'
        }
        'BehaviorMonitoring' = @{
            AlertName   = 'Suspicious ''BmTestOfflineUI'' behavior was blocked'
            HowItWorks  = 'The script runs a command where PowerShell spawns another PowerShell with the argument "hidden" followed by a test GUID. The command itself fails (CommandNotFoundException), but that is expected -- Defender behavior monitoring watches runtime process patterns, not file signatures. It sees one PowerShell launching another with suspicious arguments and flags the behavior.'
            ProcessChain = 'powershell.exe > powershell.exe "hidden 12154dfe-61a5-4357-ba5a-efecc45c34c4" (behavior flagged)'
            PortalPath  = "$portalUrl/alerts"
            WaitTime    = '2-5 minutes'
            NoisyAlert  = 'The deployment script''s nested PowerShell pattern may trigger a duplicate behavior alert. The ''BmTestOfflineUI'' alert is the intended one.'
        }
        'Pua' = @{
            AlertName   = '''EICAR_Test_File'' unwanted software was prevented'
            HowItWorks  = 'The script enables PUA protection and provides a URL to the AMTSO PUA test file. When the user downloads the file in the browser, Defender scans it and identifies it as a Potentially Unwanted Application. The download is blocked before the file reaches disk. PUA catches adware, bundlers, and browser toolbars that degrade user experience.'
            ProcessChain = 'Browser > download PotentiallyUnwanted.exe (blocked by PUA protection)'
            PortalPath  = "$portalUrl/alerts"
            WaitTime    = '1-5 minutes'
            ManualSteps = 'RDP into VM > open Edge > go to amtso.org/feature-settings-check-potentially-unwanted-applications > click the PUA test download link'
        }
        'AppReputation' = @{
            AlertName   = '''Demo'' malware was prevented (from Known Malware test)'
            HowItWorks  = 'SmartScreen in Edge checks every downloaded executable against a cloud reputation database. The demo page at demo.smartscreen.msft.net provides three test downloads: a known-safe file (downloads normally), an unknown file (SmartScreen warns before running), and a known-malicious file (SmartScreen blocks and Defender AV quarantines as Trojan:Win32/Demo). You get two layers: SmartScreen blocks in Edge AND Defender AV catches the file on disk.'
            ProcessChain = 'Edge > SmartScreen cloud lookup > block/warn based on reputation'
            PortalPath  = "$portalUrl/alerts"
            WaitTime    = '1-2 minutes (Known Malware test generates a portal alert)'
            ManualSteps = 'RDP into VM > open Edge > go to https://demo.smartscreen.msft.net > scroll to "App Rep Demos" > (1) Known Good: download + run = runs with "established reputation" message > (2) Unknown: download + run = SmartScreen warns "not commonly downloaded" > (3) Known Malware: download + run = "blocked as unsafe by Microsoft Defender SmartScreen"'
        }
        'UrlReputation' = @{
            AlertName   = 'SmartScreen URL block (browser-level red block page)'
            HowItWorks  = 'SmartScreen checks every URL visited in Edge against a cloud threat intelligence database. The demo page at demo.smartscreen.msft.net provides test URLs for phishing, malware, exploits, and malvertising. Each triggers a different response: suspicious sites get a warning, known threats get a full red block page. This is browser-level protection using Microsoft official test URLs.'
            ProcessChain = 'Edge > URL request > SmartScreen cloud check > red block page'
            PortalPath  = "$portalUrl/alerts"
            WaitTime    = 'Immediate (browser-level)'
            ManualSteps = 'RDP into VM > open Edge > go to https://demo.smartscreen.msft.net > use the "URL Rep Demos" section > test phishing, malware, blocked download, exploit, and malvertising links'
        }
        'ControlledFolder' = @{
            AlertName   = 'ControlledFolderAccessViolationBlocked (Device Timeline + Advanced Hunting)'
            HowItWorks  = 'The script creates a protected folder with sample business documents, enables Controlled Folder Access, and downloads a ransomware test executable from Microsoft. When the test file runs, it tries to encrypt files in the protected folder. CFA blocks every write attempt from the untrusted process. The files remain intact and readable.'
            ProcessChain = 'ransomware_testfile.exe > write to C:\demo (blocked by CFA)'
            PortalPath  = "$portalUrl/hunting"
            WaitTime    = '1-2 minutes'
            HuntingQuery = 'DeviceEvents | where ActionType == ''ControlledFolderAccessViolationBlocked'' | where DeviceName startswith ''win11'' | project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName | order by Timestamp desc'
            NoisyAlert  = 'Behavior monitoring may flag the unsigned ransomware test executable download/execution. The CFA block events in Advanced Hunting are the real demo evidence.'
        }
        'AsrRules' = @{
            AlertName   = 'AsrOfficeChildProcessBlocked (Advanced Hunting)'
            HowItWorks  = 'The script enabled 9 ASR rules and deployed a pre-built .docm with a VBA macro plus a one-click launcher (Run-AsrTest.bat) to the VM. When you double-click it via RDP, it sets up Office trust and opens the document. ASR rule D4F940AB blocks Word from spawning cmd.exe as a child process. ASR blocks are PREVENTION, not detection -- evidence appears in Advanced Hunting (DeviceEvents), not in the Alerts queue.'
            ProcessChain = 'WINWORD.EXE > VBA Shell("cmd.exe") > BLOCKED by ASR rule D4F940AB (Office child process)'
            PortalPath  = "$portalUrl/hunting"
            WaitTime    = '1-10 minutes for events to appear in Advanced Hunting'
            HuntingQuery= 'DeviceEvents | where ActionType == ''AsrOfficeChildProcessBlocked'' | where DeviceName startswith ''win11'' | project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessFileName | order by Timestamp desc'
        }
        'CfaTestTool' = @{
            AlertName   = 'ControlledFolderAccessViolationBlocked (Advanced Hunting -- no alert in queue)'
            HowItWorks  = 'The script enables CFA and downloads Microsoft''s dedicated CFA test tool (CFAtool.exe). When you launch the GUI tool and attempt to write to a protected folder (like Documents), CFA blocks the write because CFAtool is not a trusted application. The tool may not show an error -- the file simply won''t be created. This simulates any untrusted software trying to modify protected files.'
            ProcessChain = 'CFAtool.exe > write to protected folder (blocked by CFA)'
            PortalPath  = "$portalUrl/hunting"
            WaitTime    = '1-2 minutes'
            HuntingQuery = 'DeviceEvents | where ActionType == ''ControlledFolderAccessViolationBlocked'' | where DeviceName startswith ''win11'' | project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName | order by Timestamp desc'
            ManualSteps = 'RDP into VM > navigate to C:\MDE-Demo > double-click CFAtool.exe > in the tool, browse to C:\Users\<username>\Documents (a default protected folder) > click the Write button -- CFA blocks the write'
        }
        'ExploitProtection' = @{
            AlertName   = 'No alert -- this is a configuration demo, not a detection'
            HowItWorks  = 'The script downloads and applies a Microsoft Exploit Protection XML policy that enables system-wide mitigations: DEP (prevents code in data regions), ASLR (randomizes memory layout), CFG (validates call targets), and SEHOP (protects exception handlers). These mitigations block entire classes of memory-based exploits with zero performance impact.'
            ProcessChain = 'Set-ProcessMitigation > applies XML policy > system-wide mitigations active'
            PortalPath  = ''
            WaitTime    = 'No wait needed -- verify settings via RDP'
            ManualSteps = 'RDP into VM > open Windows Security > App and Browser Control > Exploit Protection > review System settings to confirm DEP, ASLR, CFG, SEHOP are enabled'
        }
        'NetworkProtection' = @{
            AlertName   = 'Suspicious connection blocked by network protection'
            HowItWorks  = 'The script enables Network Protection, which works at the network layer across ALL applications (not just Edge). When you open Chrome or Firefox and navigate to the test URL (smartscreentestratings2.net), Network Protection intercepts the outbound connection and blocks it. The browser shows a connection error, not a SmartScreen page -- proving this is network-layer blocking.'
            ProcessChain = 'chrome.exe/firefox.exe > outbound connection > Network Protection blocks at network layer'
            PortalPath  = "$portalUrl/incidents"
            WaitTime    = '5-15 minutes'
            ManualSteps = 'RDP into VM > open Chrome or Firefox (NOT Edge) > navigate to https://smartscreentestratings2.net'
            HuntingQuery = 'DeviceEvents | where ActionType == ''ExploitGuardNetworkProtectionBlocked'' | where DeviceName startswith ''win11'' | project Timestamp, DeviceName, ActionType, RemoteUrl, InitiatingProcessFileName | order by Timestamp desc'
            PortalNote  = 'An incident titled "Suspicious connection blocked by network protection" is created in the portal, but it can take 5-15 minutes to surface. The Advanced Hunting query below shows the same block event in 1-2 minutes -- use it for faster demo verification.'
            NoisyAlert  = '''Behavior:Win32/PShellMal.A'' -- this is the deployment script itself accessing the test URL from SYSTEM context. Ignore it; the chrome.exe block is the real demo alert.'
        }
        'EdrDetection' = @{
            AlertName   = 'Suspicious PowerShell command line'
            HowItWorks  = 'The script uses Start-Process to create a specific process chain: cmd.exe spawns powershell.exe with arguments that attempt to download a file from localhost and execute it. The download fails (expected), but EDR sees the suspicious behavior pattern -- a command prompt launching PowerShell with download-and-execute arguments. This matches known attack techniques and triggers a test alert with full process tree.'
            ProcessChain = 'cmd.exe > powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden > WebClient.DownloadFile > Start-Process invoice.exe'
            PortalPath  = "$portalUrl/alerts"
            WaitTime    = '2-10 minutes'
            NoisyAlert  = 'Behavior monitoring may also flag the deployment script''s PowerShell activity. The EDR alert with the download-and-execute process chain is the real demo alert.'
        }
    }

    $info = $alertInfo[$ScenarioName]

    # Context-aware banner title
    $taskLabel = if ($ScenarioName -eq 'Cleanup') { 'Cleanup' } else { 'Simulation' }

    if ($Success) {
        Show-PageBanner -Title "$taskLabel Complete" -Color Green
    } else {
        Show-PageBanner -Title "$taskLabel Failed" -Color Red
        Write-Host ''
        $targetLabel = if ($script:LocalMode) { 'this host' } else { 'the VM' }
        if ($ScenarioName -eq 'Cleanup') {
            Write-Host "  [X] Cleanup encountered errors on $targetLabel." -ForegroundColor Red
        } else {
            Write-Host "  [X] The simulation encountered errors on $targetLabel." -ForegroundColor Red
        }
        Write-Host '      This usually means:' -ForegroundColor Gray
        if ($script:LocalMode) {
            Write-Host '        - PowerShell is not running as Administrator' -ForegroundColor Gray
            Write-Host '        - Defender Antivirus is disabled or RTP is off' -ForegroundColor Gray
            Write-Host '        - A third-party AV is intercepting the test artifacts' -ForegroundColor Gray
        } else {
            Write-Host '        - The VM name or resource group is incorrect' -ForegroundColor Gray
            Write-Host '        - The VM is not running or not reachable' -ForegroundColor Gray
            Write-Host '        - Your account lacks Run Command permissions (RBAC)' -ForegroundColor Gray
        }
        if ($ScenarioName -ne 'Cleanup') {
            Write-Host '        - A Defender setting could not be applied' -ForegroundColor Gray
        }
        Write-Host ''
        Write-Host '      Check the log file for detailed error messages.' -ForegroundColor Gray
        if ($script:LogFile) {
            Write-Host "      Log: $script:LogFile" -ForegroundColor DarkGray
        }
    }

    if ($info) {
        # Box-drawing characters
        $tl = [char]0x2554; $tr = [char]0x2557
        $bl = [char]0x255A; $br = [char]0x255D
        $hz = [char]0x2550; $vt = [char]0x2551
        $ml = [char]0x2560; $mr = [char]0x2563
        $th = [char]0x2500

        # Card width adapts to terminal (min 62, max terminal - 4 for side margins)
        $termW = try { [Console]::WindowWidth } catch { 80 }
        $cardW = [Math]::Max(62, [Math]::Min($termW - 4, 100))
        $innerW = $cardW - 2

        $writeLine = {
            param([string]$Text, [ConsoleColor]$TextColor = 'Gray')
            $contentW = $innerW - 2
            $segments = @()
            if ($Text.Length -le $contentW) {
                $segments = @($Text)
            } else {
                $words = $Text -split '\s+'
                $line = ''
                foreach ($w in $words) {
                    while ($w.Length -gt $contentW) {
                        if ($line) { $segments += $line; $line = '' }
                        $segments += $w.Substring(0, $contentW)
                        $w = $w.Substring($contentW)
                    }
                    if (-not $w) { continue }
                    if (($line.Length + $w.Length + 1) -gt $contentW) {
                        $segments += $line
                        $line = $w
                    } else {
                        if ($line) { $line += " $w" } else { $line = $w }
                    }
                }
                if ($line) { $segments += $line }
            }
            foreach ($seg in $segments) {
                $padded = "  $seg".PadRight($innerW)
                if ($padded.Length -gt $innerW) { $padded = $padded.Substring(0, $innerW) }
                Write-Host -NoNewline "  $vt" -ForegroundColor $script:Colors.Border
                Write-Host -NoNewline $padded -ForegroundColor $TextColor
                Write-Host "$vt" -ForegroundColor $script:Colors.Border
            }
        }
        $writeEmpty = { & $writeLine -Text '' }
        $writeLabel = { param([string]$L) & $writeLine -Text $L -TextColor White }
        $writeValue = { param([string]$V) & $writeLine -Text $V -TextColor Cyan }
        $writeMuted = { param([string]$V) & $writeLine -Text $V -TextColor DarkGray }
        $writeBody  = { param([string]$V) & $writeLine -Text $V -TextColor Gray }
        $wrapText = {
            param([string]$Text, [int]$MaxLen)
            $words = $Text -split '\s+'
            $lines = @()
            $line = ''
            foreach ($word in $words) {
                # Break words longer than MaxLen into chunks
                while ($word.Length -gt $MaxLen) {
                    if ($line) { $lines += $line; $line = '' }
                    $lines += $word.Substring(0, $MaxLen)
                    $word = $word.Substring($MaxLen)
                }
                if (-not $word) { continue }
                if (($line.Length + $word.Length + 1) -gt $MaxLen) {
                    $lines += $line
                    $line = $word
                } else {
                    if ($line) { $line += " $word" } else { $line = $word }
                }
            }
            if ($line) { $lines += $line }
            $lines
        }

        # Card header
        $headerText = '  RESULTS'
        Write-Host ''
        Write-Host "  $tl$([string]::new($hz, $innerW))$tr" -ForegroundColor $script:Colors.Border
        $headerPadded = $headerText.PadRight($innerW)
        Write-Host -NoNewline "  $vt" -ForegroundColor $script:Colors.Border
        Write-Host -NoNewline $headerPadded -ForegroundColor $script:Colors.Title
        Write-Host "$vt" -ForegroundColor $script:Colors.Border
        Write-Host "  $ml$([string]::new($th, $innerW))$mr" -ForegroundColor $script:Colors.Border

        # EXPECTED ALERT
        & $writeEmpty
        & $writeLabel 'EXPECTED ALERT'
        & $writeValue $info.AlertName

        # NOISY ALERT NOTE (side-effect from deployment script)
        if ($info.ContainsKey('NoisyAlert') -and $info.NoisyAlert) {
            & $writeEmpty
            & $writeMuted "NOTE: You may also see an unrelated alert:"
            $noisyLines = & $wrapText -Text $info.NoisyAlert -MaxLen ($innerW - 4)
            foreach ($nl in $noisyLines) { & $writeMuted $nl }
        }

        # HOW IT WORKED
        & $writeEmpty
        & $writeLabel 'HOW IT WORKED'
        $descLines = & $wrapText -Text $info.HowItWorks -MaxLen ($innerW - 4)
        foreach ($dl in $descLines) { & $writeBody $dl }

        # PROCESS CHAIN
        & $writeEmpty
        & $writeLabel 'PROCESS CHAIN'
        $chainLines = & $wrapText -Text $info.ProcessChain -MaxLen ($innerW - 4)
        foreach ($cl in $chainLines) { & $writeValue $cl }

        # WHERE TO CHECK
        & $writeEmpty
        & $writeLabel 'WHERE TO CHECK'
        if ($info.PortalPath) {
            & $writeValue "Portal: $($info.PortalPath)"
        }
        if ($info.WaitTime -match 'N/A|No wait|configuration') {
            & $writeMuted "Wait:   $($info.WaitTime)"
        } else {
            & $writeMuted "Wait:   $($info.WaitTime) for alert to appear"
        }

        # Optional portal note (e.g. KQL is faster than waiting for an incident)
        if ($info.ContainsKey('PortalNote') -and $info.PortalNote) {
            $noteLines = & $wrapText -Text $info.PortalNote -MaxLen ($innerW - 4)
            foreach ($nl in $noteLines) { & $writeMuted $nl }
        }

        # ADVANCED HUNTING QUERY (for scenarios that use hunting instead of alerts)
        if ($info.ContainsKey('HuntingQuery') -and $info.HuntingQuery) {
            & $writeEmpty
            & $writeLabel 'ADVANCED HUNTING QUERY (copy to portal)'
            $queryLines = & $wrapText -Text $info.HuntingQuery -MaxLen ($innerW - 4)
            foreach ($ql in $queryLines) { & $writeLine -Text $ql -TextColor Green }
        }

        # VERIFICATION STEPS (show when scenario has manual steps)
        if ($info.ContainsKey('ManualSteps') -and $info.ManualSteps) {
            & $writeEmpty
            & $writeLabel 'HOW TO VERIFY'
            $stepLines = & $wrapText -Text $info.ManualSteps -MaxLen ($innerW - 4)
            foreach ($sl in $stepLines) { & $writeLine -Text $sl -TextColor Yellow }
        }

        # Card bottom
        & $writeEmpty
        Write-Host "  $bl$([string]::new($hz, $innerW))$br" -ForegroundColor $script:Colors.Border
    }

    if ($ScenarioName -eq 'Cleanup') {
        Write-Host ''
        if ($Success) {
            Write-Host '  [+] All simulation artifacts have been cleaned up.' -ForegroundColor Green
        } else {
            if ($script:LocalMode) {
                Write-Host '  [X] Some cleanup steps failed. Artifacts may remain on this host.' -ForegroundColor Red
                Write-Host '      Re-run cleanup as Administrator, then verify C:\MDE-Demo is gone.' -ForegroundColor Gray
            } else {
                Write-Host '  [X] Some cleanup steps failed. Artifacts may remain on the VM.' -ForegroundColor Red
                Write-Host '      Verify the VM name and resource group, then try again.' -ForegroundColor Gray
            }
        }
        Write-Host ''

        # Navigation menu for Cleanup (no portal/cleanup options)
        Write-Host '  Press Enter to continue...' -ForegroundColor $script:Colors.Muted
        Read-Host | Out-Null

        $exitCleanup = $false
        while (-not $exitCleanup) {
            $cleanupItems = @(
                @{ Label = 'Run another simulation'; Value = 'Another' }
                @{ Label = 'Try cleanup again'; Value = 'Retry' }
                @{ Label = $null; Value = $null }
                @{ Label = 'Back to main page'; Value = 'MainPage' }
                @{ Label = 'Exit'; Value = 'Exit' }
            )

            Show-PageBanner -Title 'What Next?' -Color Yellow
            $cleanupChoice = Show-InteractiveMenu -Items $cleanupItems -Title ''

            if ($null -eq $cleanupChoice) { $cleanupChoice = 'Exit' }

            switch ($cleanupChoice) {
                'Another' {
                    $script:ReturnToMenu = $true
                    $exitCleanup = $true
                }
                'Retry' {
                    # Re-run cleanup
                    $retryResult = Invoke-Scenario -ScenarioName 'Cleanup'
                    Show-PageBanner -Title $(if ($retryResult -ne $false) { 'Cleanup Complete' } else { 'Cleanup Failed' }) -Color $(if ($retryResult -ne $false) { 'Green' } else { 'Red' })
                    Write-Host ''
                    if ($retryResult -ne $false) {
                        Write-Host '  [+] All simulation artifacts have been cleaned up.' -ForegroundColor Green
                    } else {
                        Write-Host '  [X] Cleanup still encountering errors.' -ForegroundColor Red
                    }
                    Write-Host ''
                    Write-Host '  Press Enter to continue...' -ForegroundColor $script:Colors.Muted
                    Read-Host | Out-Null
                }
                'MainPage' {
                    $script:ReturnToMain = $true
                    $exitCleanup = $true
                }
                'Exit' {
                    $exitCleanup = $true
                }
            }
        }
        return
    }

    if ($ScenarioName -eq 'All') {
        Write-Host ''
        if ($script:LocalMode) {
            Write-Host "  All 13 attack simulations deployed to this host ($($script:VMName))." -ForegroundColor Green
            Write-Host '  Stay on this machine and refer to each guide for live simulation steps.' -ForegroundColor Cyan
        } else {
            Write-Host "  All 13 attack simulations deployed to $($script:VMName)." -ForegroundColor Green
            Write-Host '  RDP into the VM and refer to each guide for live simulation steps.' -ForegroundColor Cyan
        }
    }

    # Pause so the user can read simulation results before showing the menu
    Write-Host ''
    Write-Host '  Press Enter to continue...' -ForegroundColor $script:Colors.Muted
    Read-Host | Out-Null

    # ---- Post-simulation menu (loops until Exit) ----
    $exitMenu = $false
    while (-not $exitMenu) {
        $postItems = @(
            @{ Label = 'Open Defender portal (alerts page)'; Value = 'Portal' }
            @{ Label = 'Clean up simulation files from the VM'; Value = 'Cleanup' }
            @{ Label = 'Run another simulation'; Value = 'Another' }
            @{ Label = $null; Value = $null }
            @{ Label = 'Back to main page'; Value = 'MainPage' }
            @{ Label = 'Exit'; Value = 'Exit' }
        )

        Show-PageBanner -Title 'What Next?' -Color Yellow
        $postChoice = Show-InteractiveMenu -Items $postItems -Title ''

        if ($null -eq $postChoice) { $postChoice = 'Exit' }

        switch ($postChoice) {
            'Portal' {
                $alertUrl = "$portalUrl/alerts"
                Write-Host ''
                Write-Host "  Opening: $alertUrl" -ForegroundColor Cyan
                Write-Host ''
                Write-Host '  In the portal:' -ForegroundColor White
                Write-Host '    1. Go to Incidents & Alerts > Alerts' -ForegroundColor Gray
                Write-Host "    2. Look for: $($info.AlertName)" -ForegroundColor Gray
                Write-Host '    3. Click the alert to see severity, detection source, and description' -ForegroundColor Gray
                Write-Host '    4. Click Alert Story to see the full process tree' -ForegroundColor Gray
                Write-Host '    5. Click the device name to see the timeline and response actions' -ForegroundColor Gray
                Write-Host ''
                try {
                    Start-Process $alertUrl
                }
                catch {
                    Write-Log "Could not open browser. Navigate manually to: $alertUrl" -Level WARN
                }
                Write-Host '  Press Enter to continue...' -ForegroundColor $script:Colors.Muted
                Read-Host | Out-Null
            }
            'Cleanup' {
                Write-Host ''
                Write-Log 'Running cleanup...'
                $modulesDir = Join-Path $PSScriptRoot 'redtide-modules'
                $cleanupPath = Join-Path $modulesDir 'Remove-AllStrikes.ps1'
                if (Test-Path $cleanupPath) {
                    . $cleanupPath
                    Remove-AllStrikes
                    Write-Log 'Cleanup complete. All simulation files removed from the VM.' -Level SUCCESS
                }
                else {
                    Write-Log "Cleanup module not found: $cleanupPath" -Level ERROR
                }
                Write-Host ''
                Write-Host '  Press Enter to continue...' -ForegroundColor $script:Colors.Muted
                Read-Host | Out-Null
            }
            'Another' {
                $exitMenu = $true
                $script:ReturnToMenu = $true
            }
            'MainPage' {
                $exitMenu = $true
                $script:ReturnToMain = $true
            }
            'Exit' {
                $exitMenu = $true
            }
        }
    }

    Write-Host ''
}

# ---------------------------------------------------------------------------
# Region: Main
# ---------------------------------------------------------------------------

function Show-Help {
    Clear-Host
    $bc = $script:Colors.Border
    $v  = [char]0x2551
    $w  = 74

    $wr = {
        param([string]$text, $color)
        Write-Host "  $v" -NoNewline -ForegroundColor $bc
        Write-Host $text.PadRight($w) -NoNewline -ForegroundColor $color
        Write-Host "$v" -ForegroundColor $bc
    }

    Write-Host ''
    Write-Host "  $([char]0x2554)$([string]::new([char]0x2550, $w))$([char]0x2557)" -ForegroundColor $bc
    & $wr '  REDTIDE HELP' $script:Colors.Title
    Write-Host "  $([char]0x2560)$([string]::new([char]0x2550, $w))$([char]0x2563)" -ForegroundColor $bc
    & $wr '' $bc
    & $wr '  RedTide runs Defender demonstrations locally or on an Azure VM.' $script:Colors.Body
    & $wr '  Use only isolated, disposable labs. Read README.md before running.' $script:Colors.Body
    & $wr '' $bc
    & $wr '  USAGE' $script:Colors.Title
    & $wr '    Interactive:  .\Start-RedTide.ps1' $script:Colors.Menu
    & $wr '    Azure direct: .\Start-RedTide.ps1 -Scenario <name> -ResourceGroup <rg>' $script:Colors.Menu
    & $wr '                    -VMName <vm> [-SubscriptionId <id>] [-SkipChecks]' $script:Colors.Menu
    & $wr '    Local direct: .\Start-RedTide.ps1 -Local [-Scenario <name>] [-SkipChecks]' $script:Colors.Menu
    & $wr '' $bc
    & $wr '  SIMULATIONS (13)' $script:Colors.Title
    & $wr '    Next-Gen Protection (P1+)        Attack Surface Reduction (P1+)' $script:Colors.Body
    & $wr '    -------------------------        ------------------------------' $script:Colors.Muted
    & $wr '    CloudProtection                  ControlledFolder' $script:Colors.Body
    & $wr '    Amsi                             AsrRules' $script:Colors.Body
    & $wr '    AntivirusValidation              CfaTestTool' $script:Colors.Body
    & $wr '    BehaviorMonitoring               ExploitProtection' $script:Colors.Body
    & $wr '    Pua                              NetworkProtection' $script:Colors.Body
    & $wr '    AppReputation' $script:Colors.Body
    & $wr '    UrlReputation                    EDR (P2 Only)' $script:Colors.Body
    & $wr '                                     EdrDetection' $script:Colors.Body
    & $wr '' $bc
    & $wr '  PREREQUISITES (Azure mode)' $script:Colors.Title
    & $wr '    - Azure account with a running Windows VM (VM agent healthy)' $script:Colors.Body
    & $wr '    - VM onboarded to Defender for Endpoint (Sense service running)' $script:Colors.Body
    & $wr '    - Az PowerShell modules installed, logged in (Connect-AzAccount)' $script:Colors.Body
    & $wr '    - Contributor or VM Contributor RBAC on the resource group' $script:Colors.Body
    & $wr '    - Portal access at security.microsoft.com to verify alerts' $script:Colors.Body
    & $wr '' $bc
    & $wr '  PREREQUISITES (Local mode)' $script:Colors.Title
    & $wr '    - 64-bit Windows PowerShell 5.1+ running as Administrator' $script:Colors.Body
    & $wr '    - Defender Antivirus active (real-time protection on for detections)' $script:Colors.Body
    & $wr '    - Optional: host onboarded to MDE (for EDR Detection scenario)' $script:Colors.Body
    & $wr '' $bc
    & $wr '  KEY PARAMETERS' $script:Colors.Title
    & $wr '    -Scenario          Simulation name, ''All'', or ''Cleanup''' $script:Colors.Body
    & $wr '    -Local             Run on this host (skip RG / VM prompts)' $script:Colors.Body
    & $wr '    -ResourceGroup     Azure resource group containing the target VM' $script:Colors.Body
    & $wr '    -VMName            Name of the target Azure VM' $script:Colors.Body
    & $wr '    -SubscriptionId    Azure subscription (default: current Az context)' $script:Colors.Body
    & $wr '    -SkipChecks        Skip pre-flight validation checks' $script:Colors.Body
    & $wr '' $bc
    & $wr '  NAVIGATION' $script:Colors.Title
    & $wr '    Up/Down  Navigate       Enter  Select       Esc  Go back' $script:Colors.Body
    & $wr '    1-9      Jump to item   Q      Quit         ?    Help' $script:Colors.Body
    & $wr '' $bc
    Write-Host "  $([char]0x255A)$([string]::new([char]0x2550, $w))$([char]0x255D)" -ForegroundColor $bc
    Write-Host ''
    Write-Host '  Press any key to return...' -ForegroundColor $script:Colors.Muted
    $null = [Console]::ReadKey($true)
}

function Show-About {
    Clear-Host
    $bc = $script:Colors.Border
    $v  = [char]0x2551
    $w  = 74

    $wr = {
        param([string]$text, $color)
        Write-Host "  $v" -NoNewline -ForegroundColor $bc
        Write-Host $text.PadRight($w) -NoNewline -ForegroundColor $color
        Write-Host "$v" -ForegroundColor $bc
    }

    Write-Host ''
    Write-Host "  $([char]0x2554)$([string]::new([char]0x2550, $w))$([char]0x2557)" -ForegroundColor $bc
    & $wr '  ABOUT REDTIDE' $script:Colors.Title
    Write-Host "  $([char]0x2560)$([string]::new([char]0x2550, $w))$([char]0x2563)" -ForegroundColor $bc
    & $wr '' $bc
    & $wr "  RedTide v$($script:Version)" $script:Colors.Menu
    & $wr '  Attack Simulations for Endpoint Protection' $script:Colors.Body
    & $wr '' $bc
    & $wr '  Runs 13 demonstration scenarios against an Azure VM (via Run' $script:Colors.Body
    & $wr '  Command) or directly on the local host (-Local), triggering real' $script:Colors.Body
    & $wr '  Microsoft Defender for Endpoint telemetry for lab demonstrations.' $script:Colors.Body
    & $wr '' $bc
    & $wr '  Author    Carlos Suarez' $script:Colors.Body
    & $wr '  License   MIT' $script:Colors.Body
    & $wr '' $bc
    & $wr '  GitHub    github.com/Contosec-EMU/RedTide' $script:Colors.Muted
    & $wr '' $bc
    & $wr '  Microsoft Learn Defender for Endpoint demonstration scenarios:' $script:Colors.Muted
    & $wr '  learn.microsoft.com/en-us/defender-endpoint/' $script:Colors.Muted
    & $wr '    defender-endpoint-demonstrations' $script:Colors.Muted
    & $wr '' $bc
    & $wr '  This is a community tool, not an official Microsoft product.' $script:Colors.Muted
    & $wr '  Not supported or endorsed by Microsoft. Disposable labs only.' $script:Colors.Muted
    & $wr '' $bc
    Write-Host "  $([char]0x255A)$([string]::new([char]0x2550, $w))$([char]0x255D)" -ForegroundColor $bc
    Write-Host ''
    Write-Host '  Press any key to return...' -ForegroundColor $script:Colors.Muted
    $null = [Console]::ReadKey($true)
}

function Show-Banner {
    Clear-Host
    $bc = $script:Colors.Border
    $v  = [char]0x2551
    $w  = 66

    # Helper: write one box row with auto-padding to $w chars
    $wr = {
        param([string]$text, $color)
        Write-Host "  $v" -NoNewline -ForegroundColor $bc
        Write-Host $text.PadRight($w) -NoNewline -ForegroundColor $color
        Write-Host "$v" -ForegroundColor $bc
    }

    Write-Host ''
    Write-Host "  $([char]0x2554)$([string]::new([char]0x2550, $w))$([char]0x2557)" -ForegroundColor $bc
    & $wr '' $bc
    & $wr '        ____           _ _____ _     _' Red
    & $wr '       |  _ \ ___  __| |_   _(_) __| | ___' Red
    & $wr '       | |_) / _ \/ _` | | | | |/ _` |/ _ \' Red
    & $wr '       |  _ <  __/ (_| | | | | | (_| |  __/' Red
    & $wr '       |_| \_\___|\__,_| |_| |_|\__,_|\___|' Red
    & $wr '' $bc
    & $wr '       Attack Simulations for Endpoint Protection' $script:Colors.Body
    & $wr '' $bc
    Write-Host "  $([char]0x2560)$([string]::new([char]0x2550, $w))$([char]0x2563)" -ForegroundColor $bc
    & $wr '' $bc
    & $wr '  13 attack simulations that trigger real Defender alerts.' $script:Colors.Body
    & $wr '  No actual malware. Targets an Azure VM or this local host.' $script:Colors.Body
    & $wr '' $bc
    Write-Host "  $v" -NoNewline -ForegroundColor $bc
    Write-Host '  Next-Gen Protection (7)  ' -NoNewline -ForegroundColor $script:Colors.Menu
    Write-Host "$([char]0x00B7)" -NoNewline -ForegroundColor $bc
    Write-Host '  ASR (5)  ' -NoNewline -ForegroundColor $script:Colors.Menu
    Write-Host "$([char]0x00B7)" -NoNewline -ForegroundColor $bc
    Write-Host '  EDR (1)                 ' -NoNewline -ForegroundColor $script:Colors.Menu
    Write-Host "$v" -ForegroundColor $bc
    & $wr '' $bc
    Write-Host "  $([char]0x2560)$([string]::new([char]0x2550, $w))$([char]0x2563)" -ForegroundColor $bc
    & $wr '  Community project . Carlos Suarez . MIT License' $script:Colors.Muted
    Write-Host "  $([char]0x255A)$([string]::new([char]0x2550, $w))$([char]0x255D)" -ForegroundColor $bc
    Write-Host ''
    Write-Host '  BEFORE YOU START' -ForegroundColor $script:Colors.Warning
    Write-Host "  $([string]::new([char]0x2500, 60))" -ForegroundColor $script:Colors.Warning
    Write-Host ''
    Write-Host '  Disposable labs only. Changes Defender settings and test files.' -ForegroundColor $script:Colors.Warning
    Write-Host '  Cleanup is not a full rollback. Read README.md before proceeding.' -ForegroundColor $script:Colors.Warning
    Write-Host ''
    Write-Host '  You need ONE of:' -ForegroundColor $script:Colors.Title
    Write-Host '    - An Azure account with a Windows VM onboarded to MDE, or' -ForegroundColor $script:Colors.Body
    Write-Host '    - A local Windows host with Defender active (run with -Local).' -ForegroundColor $script:Colors.Body
    Write-Host '  Plus portal access at security.microsoft.com to view alerts.' -ForegroundColor $script:Colors.Body
    Write-Host ''
    Write-Host '  The pre-flight wizard will check and set up everything else' -ForegroundColor $script:Colors.Muted
    Write-Host '  (Az modules, login, VM readiness, permissions).' -ForegroundColor $script:Colors.Muted
    Write-Host ''
}

function Main {
    $exitCode = 0

    try {
        # Initialize logging
        Initialize-LogFile -Path $LogPath

        # ---- Run mode setup ----
        # Pre-fill $script:LocalMode from the -Local switch when supplied.
        # When -Local was passed on the command line, populate
        # $script:VMName / $script:ResourceGroup with host placeholders so
        # existing log lines and display messages render meaningfully.
        # When neither -Local nor any Azure target args were supplied, the
        # welcome menu below offers an interactive Local vs Cloud choice.
        if ($Local) {
            $script:LocalMode = $true
            $script:VMName = $env:COMPUTERNAME
            $script:ResourceGroup = '(local)'
        }
        $modePresetOnCli = $Local -or $ResourceGroup -or $VMName -or $SubscriptionId

        # Show banner on first launch
        Show-Banner

        # Outer loop -- returns here when user picks "Back to main page"
        $script:ReturnToMain = $true
        while ($script:ReturnToMain) {
            $script:ReturnToMain = $false

            # ---- Page 1: choose run mode (skipped if -SkipChecks or mode preset on CLI) ----
            $modeJustPicked = $false
            if (-not $modePresetOnCli -and -not $SkipChecks) {
                $modeItems = @(
                    @{ Label = "Run on this machine ($env:COMPUTERNAME) - local Defender"; Value = 'Local' }
                    @{ Label = 'Run on an Azure VM (Cloud) - via Run Command'; Value = 'Cloud' }
                    @{ Label = $null; Value = $null }
                    @{ Label = 'Exit'; Value = 'Exit' }
                )
                $welcomeCommands = @{ Oem2 = 'Help'; A = 'About' }
                $modeChoice = $null
                while ($true) {
                    $modeChoice = Show-InteractiveMenu -Items $modeItems -Title 'How would you like to proceed?' -Commands $welcomeCommands
                    if ($modeChoice -eq 'Help')  { Show-Help;  Show-Banner; continue }
                    if ($modeChoice -eq 'About') { Show-About; Show-Banner; continue }
                    break
                }
                if ($null -eq $modeChoice -or $modeChoice -eq 'Exit') {
                    Write-Host '  Goodbye.' -ForegroundColor Gray
                    return
                }

                if ($modeChoice -eq 'Local') {
                    $script:LocalMode = $true
                    $script:VMName = $env:COMPUTERNAME
                    $script:ResourceGroup = '(local)'
                    Write-Log "Run mode: LOCAL (host: $env:COMPUTERNAME)"
                }
                else {
                    $script:LocalMode = $false
                    # Clear any prior local placeholders if user previously picked Local.
                    if ($script:ResourceGroup -eq '(local)') { $script:ResourceGroup = $null }
                    if ($script:VMName -eq $env:COMPUTERNAME) { $script:VMName = $null }
                    Write-Log 'Run mode: CLOUD (Azure VM)'
                }
                $modeJustPicked = $true
            }

            # ---- Page 2: pre-flight checks vs skip ----
            $runChecks = -not $SkipChecks
            if (-not $SkipChecks) {
                # Build a contextual page title that reflects the chosen mode.
                $modeLabel = if ($script:LocalMode) { "Local mode -- $env:COMPUTERNAME" } else { 'Cloud mode -- Azure VM' }
                Show-PageBanner -Title $modeLabel -Color Cyan

                $checkItems = @(
                    @{ Label = 'Run pre-flight checks (recommended for first run)'; Value = 'Checks' }
                    @{ Label = 'Skip checks and go straight to simulations'; Value = 'Skip' }
                    @{ Label = $null; Value = $null }
                )
                # Only offer Back when the user picked the mode interactively this iteration.
                if ($modeJustPicked) {
                    $checkItems += @{ Label = 'Back to main page'; Value = 'Back' }
                }
                $checkItems += @{ Label = 'Exit'; Value = 'Exit' }

                $welcomeCommands = @{ Oem2 = 'Help'; A = 'About' }
                $checkChoice = $null
                while ($true) {
                    $checkChoice = Show-InteractiveMenu -Items $checkItems -Title 'How would you like to proceed?' -Commands $welcomeCommands
                    if ($checkChoice -eq 'Help')  { Show-Help;  Show-Banner; continue }
                    if ($checkChoice -eq 'About') { Show-About; Show-Banner; continue }
                    break
                }
                if ($null -eq $checkChoice -or $checkChoice -eq 'Exit') {
                    Write-Host '  Goodbye.' -ForegroundColor Gray
                    return
                }
                if ($checkChoice -eq 'Back') {
                    Show-Banner
                    $script:ReturnToMain = $true
                    continue
                }
                $runChecks = ($checkChoice -eq 'Checks')
            }
            else {
                Write-Log 'Pre-flight checks skipped (-SkipChecks).' -Level WARN
                # Only skip on the first pass; subsequent loops show the menu
                $SkipChecks = $false
            }

            # Store params in script scope for module access (Azure mode only;
            # local mode already populated these above with host placeholders).
            if (-not $script:LocalMode) {
                if (-not $script:ResourceGroup -and $ResourceGroup) { $script:ResourceGroup = $ResourceGroup }
                if (-not $script:VMName -and $VMName) { $script:VMName = $VMName }
                if (-not $script:SubscriptionId -and $SubscriptionId) { $script:SubscriptionId = $SubscriptionId }
            }

            # Run pre-flight checks BEFORE showing the simulation menu
            if ($runChecks) {
                if ($script:LocalMode) {
                    $preFlightOk = Test-LocalPrerequisites
                    if (-not $preFlightOk) {
                        Write-Log 'Local pre-flight checks failed. Aborting.' -Level ERROR
                        $exitCode = 1
                        return
                    }
                    $connected = Test-LocalConnection
                    if (-not $connected) {
                        $exitCode = 1
                        return
                    }
                }
                else {
                    # Collect VM info before running checks (only prompts if not already set)
                    Read-VMInfo

                    $preFlightOk = Test-Prerequisites
                    if (-not $preFlightOk) {
                        Write-Log 'Pre-flight checks failed. Aborting.' -Level ERROR
                        $exitCode = 1
                        return
                    }

                    $vmReady = Test-VmReadiness
                    if (-not $vmReady) {
                        Write-Host ''
                        $continue = Show-Confirmation -Prompt 'VM has issues. Continue anyway?' -Default 'No'
                        if (-not $continue) {
                            Write-Log 'Aborted by user after VM readiness check.' -Level WARN
                            $exitCode = 1
                            return
                        }
                        Write-Log 'Continuing despite VM readiness warnings.' -Level WARN
                    }
                }
            }
            else {
                Write-Log 'Skipping pre-flight checks.' -Level WARN
                if ($script:LocalMode) {
                    $connected = Test-LocalConnection
                    if (-not $connected) {
                        $exitCode = 1
                        return
                    }
                }
                else {
                    # Collect VM info before showing simulation menu (only prompts if not already set)
                    Read-VMInfo
                    # Verify connection, permissions, and show summary card
                    $connected = Test-VMConnection
                    if (-not $connected) {
                        $exitCode = 1
                        return
                    }
                }
            }

            # Determine scenario BEFORE capturing baseline, so Cleanup runs
            # don't accidentally snapshot the already-mutated host state.
            $selectedScenario = $Scenario
            if (-not $selectedScenario) {
                $selectedScenario = Show-Menu
                if ($selectedScenario -eq 'Exit') {
                    Write-Host '  Goodbye.' -ForegroundColor Gray
                    return
                }
                if ($selectedScenario -eq 'MainPage') {
                    $script:ReturnToMain = $true
                    Show-Banner
                    continue
                }
            }
            # Clear one-shot parameter so subsequent loops use the menu
            $Scenario = $null

            # Capture baseline before any strikes run. Skip for Cleanup so
            # we don't overwrite an earlier baseline with the mutated state.
            if (-not $script:BaselineCaptured -and $selectedScenario -ne 'Cleanup') {
                Save-DefenderBaseline | Out-Null

                Write-Host ''
                Write-Host '  Press Enter to continue to attack simulations...' -ForegroundColor DarkGray
                Read-Host | Out-Null
            }

            # Extra confirmation for local-mode Cleanup -- it runs Remove-MpThreat
            # globally on the host (clears unrelated quarantined items too).
            if ($script:LocalMode -and $selectedScenario -eq 'Cleanup') {
                Write-Host ''
                Write-Host '  LOCAL CLEANUP CONFIRMATION' -ForegroundColor $script:Colors.Warning
                Write-Host "  $([string]::new([char]0x2500, 40))" -ForegroundColor $script:Colors.Warning
                Write-Host ''
                Write-Host '  Cleanup will:' -ForegroundColor Gray
                Write-Host '    - Restore Defender settings (CFA, ASR, NetworkProtection, PUA) on THIS host' -ForegroundColor Gray
                Write-Host '    - Delete C:\MDE-Demo and C:\demo simulation folders' -ForegroundColor Gray
                Write-Host '    - Call Remove-MpThreat -- this clears ALL active Defender threats,' -ForegroundColor Yellow
                Write-Host '      not only the simulation artifacts.' -ForegroundColor Yellow
                Write-Host ''
                $cleanOk = Show-Confirmation -Prompt 'Proceed with local cleanup?' -Default 'No'
                if (-not $cleanOk) {
                    Write-Log 'Cleanup aborted by user.' -Level WARN
                    $script:ReturnToMain = $true
                    Show-Banner
                    continue
                }
            }

            Write-Log "Scenario: $selectedScenario | VM: $($script:VMName) | RG: $($script:ResourceGroup)"

            # Inner loop -- run simulations, return to simulation menu or main page
            $script:ReturnToMenu = $false
            do {
                $script:ReturnToMenu = $false
                $script:ReturnToMain = $false

                # Execute scenario
                $result = Invoke-Scenario -ScenarioName $selectedScenario
                if ($result -eq $false) {
                    Write-Log "Scenario '$selectedScenario' finished with errors." -Level WARN
                } else {
                    Write-Log "Scenario '$selectedScenario' completed successfully." -Level SUCCESS
                }

                # Pause so the user can read step output before the results card
                Write-Host ''
                Write-Host '  Press Enter to see results...' -ForegroundColor DarkGray -NoNewline
                $null = Read-Host

                # Show results and post-simulation menu
                Show-NextSteps -ScenarioName $selectedScenario -Success ($result -ne $false)

                # Handle navigation from post-simulation menu
                if ($script:ReturnToMain) {
                    Show-Banner
                    break
                }

                # If user chose "Run another simulation", show the menu again
                if ($script:ReturnToMenu) {
                    $selectedScenario = Show-Menu
                    if ($selectedScenario -eq 'Exit') {
                        Write-Host '  Goodbye.' -ForegroundColor Gray
                        $script:ReturnToMenu = $false
                        $script:ReturnToMain = $false
                    }
                    elseif ($selectedScenario -eq 'MainPage') {
                        $script:ReturnToMenu = $false
                        $script:ReturnToMain = $true
                        Show-Banner
                    }
                }
            } while ($script:ReturnToMenu)
        }

        Write-Log "Log file: $($script:LogFile)" -Level INFO
    }
    catch {
        Write-Log "Unexpected error: $_" -Level ERROR
        Write-Log $_.ScriptStackTrace -Level ERROR
        $exitCode = 2
    }
    finally {
        if ($script:LogFile) {
            Write-Log "Session ended. Exit code: $exitCode"
        }
    }

    exit $exitCode
}

Main
