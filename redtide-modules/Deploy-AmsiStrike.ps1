<#
.SYNOPSIS
    Deploys the AMSI (Antimalware Scan Interface) simulation to a target Azure VM.

.DESCRIPTION
    Creates test script files (PowerShell, VBScript, JScript) that trigger AMSI detection,
    executes the PowerShell test to demonstrate runtime blocking, and verifies the detection.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-AmsiStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log 'Step 1/6: Creating simulation directory on VM...'
    $step1 = Invoke-DemoCommand -Description 'Create C:\MDE-Demo directory' -ScriptContent @'
        New-Item -ItemType Directory -Path 'C:\MDE-Demo' -Force | Out-Null
        Write-Output 'Directory C:\MDE-Demo created.'
'@
    if (-not $step1.Success) { return $false }

    Write-Log 'Step 2/6: Verifying Defender Antivirus configuration...'
    $step2 = Invoke-DemoCommand -Description 'Check Defender AV, RTP, and Behavior Monitoring' -ScriptContent @'
        $status = Get-MpComputerStatus -ErrorAction Stop
        $prefs  = Get-MpPreference -ErrorAction Stop

        if (-not $status.AMServiceEnabled) {
            Write-Output 'FAIL: Defender Antivirus service is not running.'
        }
        elseif (-not $status.RealTimeProtectionEnabled) {
            Write-Output 'FAIL: Real-time protection is disabled.'
        }
        elseif (-not $status.BehaviorMonitorEnabled) {
            Write-Output 'FAIL: Behavior monitoring is disabled. Enabling...'
            Set-MpPreference -DisableBehaviorMonitoring $false
            Write-Output 'Behavior monitoring enabled.'
        }
        else {
            Write-Output 'OK: Defender AV is active, real-time protection on, behavior monitoring on.'
        }

        Write-Output "RealTimeProtection: $($status.RealTimeProtectionEnabled) | BehaviorMonitor: $($status.BehaviorMonitorEnabled)"
'@
    if (-not $step2.Success) { return $false }

    if ($step2.Output -match '^FAIL:.*not running') {
        Write-Log 'Defender AV is not running on the VM. Cannot proceed.' -Level ERROR
        return $false
    }

    Write-Log 'Step 3/6: Creating AMSI test script files on VM...'
    $step3 = Invoke-DemoCommand -Description 'Create AMSI test scripts (PS1, VBS, JS)' -ScriptContent @'
        $demoDir = 'C:\MDE-Demo'

        # PowerShell test script
        $ps1Content = @"
`$testString = "AMSI Test Sample: " + "7e72c3ce-861b-4339-8740-0ac1484c1386"
Invoke-Expression `$testString
"@
        Set-Content -Path "$demoDir\AMSI_test.ps1" -Value $ps1Content -Force

        # VBScript test script
        $vbsContent = @"
Dim result : result = eval("AMSI Test Sample: " + "7e72c3ce-861b-4339-8740-0ac1484c1386") : WScript.Echo result
"@
        Set-Content -Path "$demoDir\AMSI_test.vbs" -Value $vbsContent -Force

        # JScript test script
        $jsContent = @"
var result = eval("AMSI Test Sample: " + "7e72c3ce-861b-4339-8740-0ac1484c1386");
WScript.Echo(result);
"@
        Set-Content -Path "$demoDir\AMSI_test.js" -Value $jsContent -Force

        Write-Output 'Created AMSI_test.ps1, AMSI_test.vbs, AMSI_test.js in C:\MDE-Demo'
'@
    if (-not $step3.Success) { return $false }

    Write-Log 'Step 4/6: Executing PowerShell AMSI test (expect detection)...'
    $step4 = Invoke-DemoCommand -Description 'Run AMSI_test.ps1 to trigger detection' -ExpectErrors -ScriptContent @'
        try {
            powershell.exe -ExecutionPolicy Bypass -File 'C:\MDE-Demo\AMSI_test.ps1' 2>&1
            Write-Output 'WARN: Script executed without being blocked. AMSI may not be active.'
        }
        catch {
            Write-Output "OK: Script was blocked by AMSI as expected. Error: $_"
        }
        # Either outcome is informative -- the script may be blocked silently
        Write-Output 'AMSI test execution completed.'
'@
    if (-not $step4.Success) { return $false }

    Write-Log 'Step 5/6: Verifying AMSI detection in Defender threat log...'
    $step5 = Invoke-DemoCommand -Description 'Check Get-MpThreat for AMSI detection' -ScriptContent @'
        Start-Sleep -Seconds 5
        $threats = Get-MpThreat -ErrorAction SilentlyContinue
        if ($threats) {
            $amsiThreats = $threats | Where-Object { $_.ThreatName -like '*amsi*' -or $_.ThreatName -like '*MpTest*' }
            if ($amsiThreats) {
                Write-Output 'OK: AMSI detection confirmed.'
                foreach ($t in $amsiThreats) {
                    Write-Output "  Threat: $($t.ThreatName) | Status: $($t.IsActive)"
                }
            }
            else {
                Write-Output 'WARN: Threats found but none matched AMSI pattern. Listing all:'
                foreach ($t in $threats) {
                    Write-Output "  Threat: $($t.ThreatName)"
                }
            }
        }
        else {
            Write-Output 'WARN: No threats recorded yet. Detection may take a moment to appear.'
        }
'@
    if (-not $step5.Success) { return $false }

    Write-Log 'Step 6/6: Logging final status...'
    $step6 = Invoke-DemoCommand -Description 'List simulation files' -ScriptContent @'
        $files = Get-ChildItem -Path 'C:\MDE-Demo' -ErrorAction SilentlyContinue
        Write-Output 'Files in C:\MDE-Demo:'
        foreach ($f in $files) {
            Write-Output "  $($f.Name) ($($f.Length) bytes)"
        }
'@

    Write-Log 'AMSI simulation deployed.' -Level SUCCESS
    Write-Log 'Test scripts are in C:\MDE-Demo\ (AMSI_test.ps1, .vbs, .js).' -Level INFO
    Write-Log 'During the simulation, run each script to show AMSI blocking script-based attacks.' -Level INFO
    return $true
}
