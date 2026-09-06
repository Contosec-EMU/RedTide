<#
.SYNOPSIS
    Deploys the EICAR Antivirus Validation simulation to a target Azure VM.

.DESCRIPTION
    Creates the EICAR test file on the VM to validate that Defender AV is active,
    real-time protection is working, and threat reporting is functional.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-AntivirusValidationStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log 'Step 1/4: Creating simulation directory on VM...'
    $step1 = Invoke-DemoCommand -Description 'Create C:\MDE-Demo directory' -ScriptContent @'
        New-Item -ItemType Directory -Path 'C:\MDE-Demo' -Force | Out-Null
        Write-Output 'Directory C:\MDE-Demo created.'
'@
    if (-not $step1.Success) { return $false }

    Write-Log 'Step 2/4: Verifying Defender Antivirus is active with real-time protection...'
    $step2 = Invoke-DemoCommand -Description 'Check Defender AV and RTP status' -ScriptContent @'
        $status = Get-MpComputerStatus -ErrorAction Stop

        if (-not $status.AMServiceEnabled) {
            Write-Output 'FAIL: Defender Antivirus service is not running.'
        }
        elseif (-not $status.RealTimeProtectionEnabled) {
            Write-Output 'FAIL: Real-time protection is disabled.'
        }
        elseif (-not $status.AntivirusEnabled) {
            Write-Output 'FAIL: Antivirus is disabled.'
        }
        else {
            Write-Output 'OK: Defender AV is active and real-time protection is enabled.'
        }

        Write-Output "AMServiceEnabled: $($status.AMServiceEnabled) | RealTimeProtection: $($status.RealTimeProtectionEnabled) | AntivirusEnabled: $($status.AntivirusEnabled)"
'@
    if (-not $step2.Success) { return $false }

    if ($step2.Output -match '^FAIL:.*not running') {
        Write-Log 'Defender AV is not running on the VM. Cannot proceed.' -Level ERROR
        return $false
    }
    if ($step2.Output -match '^FAIL:.*disabled') {
        Write-Log 'Real-time protection or antivirus is disabled. Cannot proceed.' -Level ERROR
        return $false
    }

    Write-Log 'Step 3/4: Writing EICAR test file (expect immediate detection and quarantine)...'
    $step3 = Invoke-DemoCommand -Description 'Create EICAR test file to trigger detection' -ExpectErrors -ScriptContent @'
        $eicarString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        $filePath = 'C:\MDE-Demo\EICAR-test.txt'

        try {
            [System.IO.File]::WriteAllText($filePath, $eicarString)
            Write-Output "EICAR file written to $filePath"
        }
        catch {
            # Write may fail if Defender intercepts during creation -- this is expected
            Write-Output "EXPECTED: File write was blocked or file was immediately quarantined."
        }

        # Brief pause to let Defender process the detection
        Start-Sleep -Seconds 3

        if (Test-Path $filePath) {
            Write-Output 'WARN: EICAR file still exists -- Defender may not have detected it yet.'
        }
        else {
            Write-Output 'OK: EICAR file was quarantined by Defender (file no longer on disk).'
        }
'@
    if (-not $step3.Success) { return $false }

    Write-Log 'Step 4/4: Verifying threat detection in Defender...'
    $step4 = Invoke-DemoCommand -Description 'Check Get-MpThreat for EICAR detection' -ScriptContent @'
        Start-Sleep -Seconds 5
        $threats = Get-MpThreat -ErrorAction SilentlyContinue

        if ($threats) {
            $eicarThreat = $threats | Where-Object { $_.ThreatName -like '*EICAR*' -or $_.ThreatName -like '*TestFile*' }
            if ($eicarThreat) {
                Write-Output "OK: EICAR detection confirmed."
                Write-Output "ThreatName: $($eicarThreat.ThreatName | Select-Object -First 1)"
                Write-Output "StatusID: $($eicarThreat.ThreatStatusID | Select-Object -First 1)"
            }
            else {
                Write-Output "WARN: Threats found but none match EICAR. Listing all:"
                foreach ($t in $threats) {
                    Write-Output "  $($t.ThreatName) (Status: $($t.ThreatStatusID))"
                }
            }
        }
        else {
            Write-Output 'WARN: No threats returned by Get-MpThreat. Detection may still be processing.'
            Write-Output 'Check the Defender portal for the alert within a few minutes.'
        }
'@

    Write-Log 'Antivirus Validation simulation deployed.' -Level SUCCESS
    Write-Log 'The EICAR test file triggers a real detection -- Defender quarantines it immediately.' -Level INFO
    Write-Log 'Check the Defender portal for the corresponding alert.' -Level INFO
    return $true
}
