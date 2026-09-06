<#
.SYNOPSIS
    Deploys the CFA Test Tool (Block Script) simulation to a target Azure VM.

.DESCRIPTION
    Enables Controlled Folder Access and downloads Microsoft's CFA test tool
    (CFAtool.exe) to C:\MDE-Demo\. The test tool is a GUI application that
    requires an interactive desktop session to run.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-CfaTestToolStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log 'Step 1/5: Creating simulation directory on VM...'
    $step1 = Invoke-DemoCommand -Description 'Create C:\MDE-Demo directory' -ScriptContent @'
        New-Item -ItemType Directory -Path 'C:\MDE-Demo' -Force | Out-Null
        Write-Output 'Directory C:\MDE-Demo created.'
'@
    if (-not $step1.Success) { return $false }

    Write-Log 'Step 2/5: Verifying Defender Antivirus is active...'
    $step2 = Invoke-DemoCommand -Description 'Check Defender AV status' -ScriptContent @'
        $status = Get-MpComputerStatus -ErrorAction Stop

        if (-not $status.AMServiceEnabled) {
            Write-Output 'FAIL: Defender Antivirus service is not running.'
        }
        elseif (-not $status.RealTimeProtectionEnabled) {
            Write-Output 'FAIL: Real-time protection is disabled.'
        }
        else {
            Write-Output 'OK: Defender AV is active, real-time protection on.'
        }
'@
    if (-not $step2.Success) { return $false }

    if ($step2.Output -match '^FAIL:.*not running') {
        Write-Log 'Defender AV is not running on the VM. Cannot proceed.' -Level ERROR
        return $false
    }

    Write-Log 'Step 3/5: Enabling Controlled Folder Access...'
    $step3 = Invoke-DemoCommand -Description 'Enable CFA' -ScriptContent @'
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'

        # Override via policy registry if Intune/GPO manages CFA
        if (Test-Path $policyPath) {
            $policyVal = (Get-ItemProperty $policyPath -Name EnableControlledFolderAccess -ErrorAction SilentlyContinue).EnableControlledFolderAccess
            if ($null -ne $policyVal -and $policyVal -ne 1) {
                Write-Output "POLICY_OVERRIDE: Intune/GPO policy key is $policyVal. Overriding to 1 (block)."
                Set-ItemProperty $policyPath -Name EnableControlledFolderAccess -Value 1
            }
        }

        # Also set via preference (works when no policy manages CFA)
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 3

        $cfa = (Get-MpPreference).EnableControlledFolderAccess
        $effectivePolicy = $null
        if (Test-Path $policyPath) {
            $effectivePolicy = (Get-ItemProperty $policyPath -Name EnableControlledFolderAccess -ErrorAction SilentlyContinue).EnableControlledFolderAccess
        }
        Write-Output "CFA preference: $cfa | Policy registry: $effectivePolicy"
'@
    if (-not $step3.Success) { return $false }

    Write-Log 'Step 4/5: Downloading CFA test tool (CFAtool.exe)...'
    $step4 = Invoke-DemoCommand -Description 'Download CFAtool.exe' -ScriptContent @'
        $testToolUrl = 'https://demo.wd.microsoft.com/Content/CFAtool.exe'
        $destPath = 'C:\MDE-Demo\CFAtool.exe'

        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -Uri $testToolUrl -OutFile $destPath -UseBasicParsing -ErrorAction Stop
            Write-Output "Downloaded CFAtool.exe to $destPath"
            Write-Output "File size: $((Get-Item $destPath).Length) bytes"
        }
        catch {
            Write-Output "WARN: Could not download CFAtool.exe: $_"
            Write-Output "Manual download needed from: $testToolUrl"
        }
'@
    if (-not $step4.Success) { return $false }

    Write-Log 'Step 5/5: Verifying CFA is enabled and tool is present...'
    $step5 = Invoke-DemoCommand -Description 'Verify CFA simulation setup' -ScriptContent @'
        Write-Output "=== CFA Test Tool Simulation Status ==="
        Write-Output "CFA Enabled: $((Get-MpPreference).EnableControlledFolderAccess)"
        Write-Output ""
        Write-Output "Simulation files:"
        if (Test-Path 'C:\MDE-Demo\CFAtool.exe') {
            $item = Get-Item 'C:\MDE-Demo\CFAtool.exe'
            Write-Output "  CFAtool.exe ($($item.Length) bytes) -- ready"
        } else {
            Write-Output "  CFAtool.exe -- NOT FOUND (manual download needed)"
        }
'@

    Write-Log 'CFA Test Tool simulation setup complete.' -Level SUCCESS
    Write-Log 'PARTIALLY AUTOMATED: CFAtool.exe is a GUI app that requires an interactive desktop.' -Level WARN
    Write-Log 'RDP into the VM > navigate to C:\MDE-Demo\ > double-click CFAtool.exe to run the simulation.' -Level INFO
    return $true
}
