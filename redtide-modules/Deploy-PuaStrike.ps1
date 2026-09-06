<#
.SYNOPSIS
    Deploys the PUA (Potentially Unwanted Application) detection simulation to a target Azure VM.

.DESCRIPTION
    Enables PUA protection and attempts to download the AMTSO PUA test file to C:\MDE-Demo\.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-PuaStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log 'Step 1/7: Creating simulation directory on VM...'
    $step1 = Invoke-DemoCommand -Description 'Create C:\MDE-Demo directory' -ScriptContent @'
        New-Item -ItemType Directory -Path 'C:\MDE-Demo' -Force | Out-Null
        Write-Output 'Directory C:\MDE-Demo created.'
'@
    if (-not $step1.Success) { return $false }

    Write-Log 'Step 2/7: Verifying Defender Antivirus is active...'
    $step2 = Invoke-DemoCommand -Description 'Check Defender AV status' -ScriptContent @'
        $status = Get-MpComputerStatus -ErrorAction Stop

        if (-not $status.AMServiceEnabled) {
            Write-Output 'FAIL: Defender Antivirus service is not running.'
        }
        elseif (-not $status.RealTimeProtectionEnabled) {
            Write-Output 'FAIL: Real-time protection is disabled.'
        }
        else {
            Write-Output 'OK: Defender AV is active and real-time protection is on.'
        }

        Write-Output "AMServiceEnabled: $($status.AMServiceEnabled)"
        Write-Output "RealTimeProtection: $($status.RealTimeProtectionEnabled)"
'@
    if (-not $step2.Success) { return $false }

    if ($step2.Output -match '^FAIL:.*not running') {
        Write-Log 'Defender AV is not running on the VM. Cannot proceed.' -Level ERROR
        return $false
    }

    Write-Log 'Step 3/7: Enabling PUA protection...'
    $step3 = Invoke-DemoCommand -Description 'Enable PUA protection via Set-MpPreference' -ScriptContent @'
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
        Write-Output 'PUA protection preference set to Enabled.'
'@
    if (-not $step3.Success) { return $false }

    Write-Log 'Step 4/7: Verifying PUA protection is enabled...'
    $step4 = Invoke-DemoCommand -Description 'Verify PUA protection setting' -ScriptContent @'
        $prefs = Get-MpPreference -ErrorAction Stop
        $puaValue = $prefs.PUAProtection

        if ($puaValue -eq 1) {
            Write-Output 'OK: PUA protection is enabled (PUAProtection = 1).'
        }
        else {
            Write-Output "WARN: PUA protection value is $puaValue (expected 1)."
        }

        Write-Output "PUAProtection: $puaValue"
'@
    if (-not $step4.Success) { return $false }

    Write-Log 'Step 5/7: Attempting PUA test file download (expect block)...'
    $step5 = Invoke-DemoCommand -Description 'Download AMTSO PUA test file' -ExpectErrors -ScriptContent @'
        $testUrl = 'http://amtso.eicar.org/PotentiallyUnwanted.exe'
        $destPath = 'C:\MDE-Demo\PotentiallyUnwanted.exe'
        $ProgressPreference = 'SilentlyContinue'

        try {
            Invoke-WebRequest -Uri $testUrl -OutFile $destPath -UseBasicParsing -ErrorAction Stop
            if (Test-Path $destPath) {
                Write-Output "File downloaded to $destPath -- Defender may quarantine it shortly."
                Write-Output "File size: $((Get-Item $destPath).Length) bytes"
            }
        }
        catch {
            Write-Output "Download blocked or failed: $_"
            Write-Output 'This is expected if PUA protection intercepted the download.'
        }
'@
    if (-not $step5.Success) { return $false }

    Write-Log 'Step 6/7: Checking for PUA detections...'
    $step6 = Invoke-DemoCommand -Description 'Check PUA threat detections' -ScriptContent @'
        Start-Sleep -Seconds 5
        $threats = Get-MpThreat -ErrorAction SilentlyContinue

        if ($threats) {
            Write-Output 'Threats detected:'
            foreach ($t in $threats) {
                Write-Output "  ThreatName: $($t.ThreatName)"
                Write-Output "  Status: $($t.ThreatStatusID)"
                Write-Output "  Resources: $($t.Resources -join ', ')"
                Write-Output '  ---'
            }
        }
        else {
            Write-Output 'No threats detected yet. The browser-based test may be needed for reliable detection.'
        }
'@
    if (-not $step6.Success) { return $false }

    Write-Log 'Step 7/7: Setup complete.'
    Write-Log 'PUA protection is enabled on the VM.' -Level SUCCESS
    Write-Log 'For the live simulation, open a browser on the VM and navigate to:' -Level INFO
    Write-Log '  http://www.amtso.org/feature-settings-check-potentially-unwanted-applications/' -Level INFO
    Write-Log 'Click the download link on that page to trigger PUA detection.' -Level INFO
    return $true
}
