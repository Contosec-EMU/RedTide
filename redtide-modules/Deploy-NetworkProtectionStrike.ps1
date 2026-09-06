<#
.SYNOPSIS
    Deploys the Network Protection simulation to a target Azure VM.

.DESCRIPTION
    Enables Network Protection and validates the configuration on the VM.
    Called by Start-RedTide.ps1 -- do not run directly.

.NOTES
    PARTIALLY AUTOMATABLE: Setup is automated, but the best visual simulation
    requires a browser (Chrome or Firefox -- NOT Edge) via RDP.
#>

function Deploy-NetworkProtectionStrike {
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
            Write-Output 'OK: Defender AV is active and real-time protection is on.'
        }
'@
    if (-not $step2.Success) { return $false }

    if ($step2.Output -match '^FAIL:.*not running') {
        Write-Log 'Defender AV is not running on the VM. Cannot proceed.' -Level ERROR
        return $false
    }

    Write-Log 'Step 3/5: Enabling Network Protection...'
    $step3 = Invoke-DemoCommand -Description 'Enable Network Protection' -ScriptContent @'
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
        Write-Output 'Network Protection set to Enabled.'
'@
    if (-not $step3.Success) { return $false }

    Write-Log 'Step 4/5: Verifying Network Protection is enabled...'
    $step4 = Invoke-DemoCommand -Description 'Verify Network Protection setting' -ScriptContent @'
        $prefs = Get-MpPreference -ErrorAction Stop
        $npValue = $prefs.EnableNetworkProtection

        switch ($npValue) {
            0 { Write-Output "FAIL: Network Protection is Disabled (value: $npValue)." }
            1 { Write-Output "OK: Network Protection is Enabled (value: $npValue)." }
            2 { Write-Output "OK: Network Protection is in Audit mode (value: $npValue)." }
            default { Write-Output "WARN: Unknown Network Protection value: $npValue" }
        }
'@
    if (-not $step4.Success) { return $false }

    if ($step4.Output -match '^FAIL:') {
        Write-Log 'Network Protection could not be enabled. Check Group Policy or tamper protection.' -Level ERROR
        return $false
    }

    Write-Log 'Step 5/5: Attempting headless validation against test URL...'
    $step5 = Invoke-DemoCommand -Description 'Test connection to smartscreentestratings2.net' -ExpectErrors -ScriptContent @'
        $testUrl = 'https://smartscreentestratings2.net/'
        try {
            $response = Invoke-WebRequest -Uri $testUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            Write-Output "WARN: Connection succeeded (HTTP $($response.StatusCode)). Network Protection may not be blocking."
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match 'actively refused|connection was blocked|unable to connect') {
                Write-Output "OK: Connection blocked as expected. Network Protection is working."
            }
            else {
                Write-Output "INFO: Connection failed: $msg"
                Write-Output "This may indicate Network Protection blocked the request (expected behavior)."
            }
        }
'@
    # Step 5 is informational -- do not fail the deployment on its result

    Write-Log 'Network Protection simulation deployed.' -Level SUCCESS
    Write-Log 'IMPORTANT: The visual simulation requires RDP and a non-Edge browser.' -Level WARN
    Write-Log 'Do NOT use Edge -- it has its own SmartScreen. Use Chrome or Firefox.' -Level WARN
    Write-Log 'RDP into the VM, open Chrome or Firefox, and navigate to:' -Level INFO
    Write-Log '  https://smartscreentestratings2.net/' -Level INFO
    Write-Log 'Network Protection will block the page and show a notification.' -Level INFO
    return $true
}
