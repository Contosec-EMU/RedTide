<#
.SYNOPSIS
    Deploys the Behavior Monitoring simulation to a target Azure VM.

.DESCRIPTION
    Verifies Defender AV configuration and runs the behavior monitoring test command.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-BehaviorMonitoringStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log 'Step 1/4: Creating simulation directory on VM...'
    $step1 = Invoke-DemoCommand -Description 'Create C:\MDE-Demo directory' -ScriptContent @'
        New-Item -ItemType Directory -Path 'C:\MDE-Demo' -Force | Out-Null
        Write-Output 'Directory C:\MDE-Demo created.'
'@
    if (-not $step1.Success) { return $false }

    Write-Log 'Step 2/4: Verifying Defender Antivirus configuration...'
    $step2 = Invoke-DemoCommand -Description 'Check Defender AV settings' -ScriptContent @'
        $status = Get-MpComputerStatus -ErrorAction Stop
        $prefs = Get-MpPreference -ErrorAction Stop

        $results = @{
            AMRunning          = $status.AMServiceEnabled
            RealTimeProtection = $status.RealTimeProtectionEnabled
            AntivirusEnabled   = $status.AntivirusEnabled
            CloudProtection    = $prefs.MAPSReporting
        }

        if (-not $status.AMServiceEnabled) {
            Write-Output 'FAIL: Defender Antivirus service is not running.'
        }
        elseif (-not $status.RealTimeProtectionEnabled) {
            Write-Output 'FAIL: Real-time protection is disabled.'
        }
        elseif ($prefs.MAPSReporting -eq 0) {
            Write-Output 'Cloud-delivered protection is disabled. Enabling...'
            Set-MpPreference -MAPSReporting Advanced
            Write-Output 'Cloud-delivered protection enabled.'
        }
        else {
            Write-Output 'OK: Defender AV is active, real-time protection on, cloud protection on.'
        }

        Write-Output "MAPSReporting: $($prefs.MAPSReporting)"
'@
    if (-not $step2.Success) { return $false }

    if ($step2.Output -match '^FAIL:.*not running') {
        Write-Log 'Defender AV is not running on the VM. Cannot proceed.' -Level ERROR
        return $false
    }

    Write-Log 'Step 3/4: Running behavior monitoring test command...'
    $step3 = Invoke-DemoCommand -Description 'Execute behavior monitoring test' -ExpectErrors -ScriptContent @'
        # This command triggers a behavior-based detection.
        # The "hidden" argument causes a CommandNotFoundException -- that is expected.
        # Defender detects the suspicious PowerShell behavior pattern, not the command itself.
        try {
            powershell.exe -NoExit -Command "powershell.exe hidden 12154dfe-61a5-4357-ba5a-efecc45c34c4"
        }
        catch {
            # Expected -- the test command intentionally errors
        }
        Write-Output 'Behavior monitoring test command executed.'
'@
    if (-not $step3.Success) { return $false }

    Write-Log 'Step 4/4: Verifying detection...'
    $step4 = Invoke-DemoCommand -Description 'Check for behavior monitoring detection' -ScriptContent @'
        Start-Sleep -Seconds 10
        $threats = Get-MpThreat -ErrorAction SilentlyContinue
        if ($threats) {
            foreach ($t in $threats) {
                Write-Output "Threat: $($t.ThreatName) | Status: $($t.ThreatStatusID)"
            }
            if ($threats.ThreatName -match 'BmTestOfflineUI') {
                Write-Output 'OK: Behavior monitoring detection confirmed (Behavior:Win32/BmTestOfflineUI).'
            }
            else {
                Write-Output 'WARN: Threats found but BmTestOfflineUI not yet detected. Check the portal -- detection may take a few minutes.'
            }
        }
        else {
            Write-Output 'WARN: No threats found yet. Detection may take a few minutes to appear.'
        }
'@

    Write-Log 'Behavior Monitoring simulation deployed.' -Level SUCCESS
    Write-Log 'NOTE: The test command produces a CommandNotFoundException -- that is expected.' -Level WARN
    Write-Log 'Look for alert "Suspicious BmTestOfflineUI behavior was blocked" in the portal.' -Level INFO
    return $true
}
