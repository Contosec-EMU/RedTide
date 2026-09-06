<#
.SYNOPSIS
    Deploys the Attack Surface Reduction Rules simulation to a target Azure VM.

.DESCRIPTION
    Retrieves Microsoft's public Office child-process demonstration document,
    verifies its SHA256 before configuring the target, then enables 9 ASR rules
    and deploys the document with an interactive launcher.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-AsrRulesStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # Verify the official sample in memory before any target configuration commands.
    $sampleUrl = 'https://demo.wd.microsoft.com/Content/TestFile_OfficeChildProcess_D4F940AB-401B-4EFC-AADC-AD5F3C50688A.docm'
    $expectedHash = 'f5ec6a746f5d70212a8779e33722964c9ede5c23b3e171cd01e68b1a6c954e86'
    $response = $null
    $responseStream = $null
    try {
        Write-Log 'Downloading the official Microsoft Office child-process ASR sample...'
        $response = Invoke-WebRequest -Uri $sampleUrl -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 0 -ErrorAction Stop
        if ($response.StatusCode -ne 200) {
            throw "Unexpected HTTP status: $($response.StatusCode)"
        }
        $responseStream = $response.RawContentStream
        [byte[]]$sampleBytes = $responseStream.ToArray()
        if ($sampleBytes.Length -lt 4 -or
            $sampleBytes[0] -ne 0x50 -or $sampleBytes[1] -ne 0x4B -or
            $sampleBytes[2] -ne 0x03 -or $sampleBytes[3] -ne 0x04) {
            throw 'The response is not a DOCM ZIP package (it may be an HTML error page).'
        }
        $responseStream.Position = 0
        $actualHash = (Get-FileHash -InputStream $responseStream -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($actualHash -ne $expectedHash) {
            throw 'The Microsoft sample SHA256 does not match the reviewed version. See README.md.'
        }
        $docmBase64 = [Convert]::ToBase64String($sampleBytes)
    }
    catch {
        Write-Log "ASR sample retrieval failed; no scenario commands were sent to the target. $_" -Level ERROR
        return $false
    }
    finally {
        if ($responseStream -is [System.IDisposable]) {
            $responseStream.Dispose()
        }
    }

    Write-Log 'Step 1/6: Creating ASR simulation directory on VM...'
    $step1 = Invoke-DemoCommand -Description 'Create C:\MDE-Demo\asr-tests directory' -ScriptContent @'
        New-Item -ItemType Directory -Path 'C:\MDE-Demo\asr-tests' -Force | Out-Null
        Write-Output 'Directory C:\MDE-Demo\asr-tests created.'
'@
    if (-not $step1.Success) { return $false }

    Write-Log 'Step 2/6: Verifying Defender Antivirus is active...'
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

    Write-Log 'Step 3/6: Enabling ASR rules in Block mode...'
    $step3 = Invoke-DemoCommand -Description 'Enable ASR rules via preference + policy registry' -ScriptContent @'
        $rules = @{
            'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email client and webmail'
            'D4F940AB-401B-4EfC-AADC-AD5F3C50688A' = 'Block Office child processes'
            '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office creating executable content'
            'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JS/VBS launching executables'
            '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block execution of potentially obfuscated scripts'
            '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
            'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted/unsigned processes from USB'
            'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Use advanced protection against ransomware'
            '33DDEDF1-C6E0-47CB-833E-DE6133960387' = 'Block Safe Mode reboot'
        }

        # Try Add-MpPreference first (works when no Intune/GPO policy manages ASR)
        foreach ($id in $rules.Keys) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions 1 -ErrorAction Stop
                Write-Output "Enabled (Block): $($rules[$id]) ($id)"
            }
            catch {
                Write-Output "WARN: Could not enable rule $id -- $_"
            }
        }

        # Also write to the policy registry to handle Intune/GPO override.
        # When Intune manages ASR, Add-MpPreference is silently ignored.
        $asrPolicyPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
        $rulesPolicyPath = "$asrPolicyPath\Rules"

        if (-not (Test-Path $asrPolicyPath)) {
            New-Item -Path $asrPolicyPath -Force | Out-Null
        }
        Set-ItemProperty -Path $asrPolicyPath -Name 'ExploitGuard_ASR_Rules' -Value 1 -Type DWord -Force
        Write-Output 'POLICY: Set ExploitGuard_ASR_Rules = 1 (enabled)'

        if (-not (Test-Path $rulesPolicyPath)) {
            New-Item -Path $rulesPolicyPath -Force | Out-Null
        }

        $policyOverrideCount = 0
        foreach ($id in $rules.Keys) {
            $current = (Get-ItemProperty $rulesPolicyPath -Name $id -ErrorAction SilentlyContinue).$id
            if ($current -ne 1) {
                New-ItemProperty -Path $rulesPolicyPath -Name $id -Value 1 -PropertyType String -Force | Out-Null
                $policyOverrideCount++
            }
        }
        if ($policyOverrideCount -gt 0) {
            Write-Output "POLICY_OVERRIDE: Wrote $policyOverrideCount ASR rules to policy registry as Block (1)."
        } else {
            Write-Output 'POLICY: All ASR rules already set to Block in policy registry.'
        }

        Start-Sleep -Seconds 5
        Write-Output 'ASR rule enablement complete.'
'@
    if (-not $step3.Success) { return $false }

    if ($step3.Output -match 'POLICY_OVERRIDE') {
        Write-Log 'Intune/GPO was managing ASR rules. Wrote rules directly to policy registry for this demo.' -Level WARN
    }

    Write-Log 'Step 4/6: Deploying ASR test document to VM...'
    # Also deploy a .bat launcher that sets up Office Trusted Location for the
    # current user and opens the .docm (so macros auto-run without prompts).
    $step5 = Invoke-DemoCommand -Description 'Deploy .docm and launcher to VM' -ScriptContent @"
        `$docmPath = 'C:\MDE-Demo\asr-tests\ASR-Test-OpenMe.docm'
        `$batPath  = 'C:\MDE-Demo\asr-tests\Run-AsrTest.bat'
        `$ps1Path  = 'C:\MDE-Demo\asr-tests\Run-AsrTest.ps1'

        # Decode the .docm from base64
        [System.IO.File]::WriteAllBytes(`$docmPath, [Convert]::FromBase64String('$docmBase64'))
        Write-Output "DOCM_DEPLOYED: `$docmPath"

        # PowerShell helper: sets Trusted Location for current user, then opens doc
        `$ps1Content = @'
# Sets Office Trusted Location so the macro auto-runs, then opens the doc.
`$trustPath = 'HKCU:\Software\Microsoft\Office\16.0\Word\Security\Trusted Locations\Location99'
if (-not (Test-Path `$trustPath)) { New-Item -Path `$trustPath -Force | Out-Null }
Set-ItemProperty -Path `$trustPath -Name 'Path' -Value 'C:\MDE-Demo\asr-tests\' -Type String -Force
Set-ItemProperty -Path `$trustPath -Name 'AllowSubFolders' -Value 0 -Type DWord -Force
`$secPath = 'HKCU:\Software\Microsoft\Office\16.0\Word\Security'
if (-not (Test-Path `$secPath)) { New-Item -Path `$secPath -Force | Out-Null }
Set-ItemProperty -Path `$secPath -Name 'AccessVBOM' -Value 1 -Type DWord -Force
Write-Host 'Office trust configured. Opening test document...' -ForegroundColor Cyan
Start-Process 'C:\MDE-Demo\asr-tests\ASR-Test-OpenMe.docm'
Write-Host 'ASR should block cmd.exe. Check for Defender notification.' -ForegroundColor Green
pause
'@
        `$ps1Content | Out-File -FilePath `$ps1Path -Encoding utf8 -Force

        # Batch launcher so users can double-click
        '@echo off' + [char]13 + [char]10 + 'powershell.exe -ExecutionPolicy Bypass -File ""C:\MDE-Demo\asr-tests\Run-AsrTest.ps1""' | Out-File -FilePath `$batPath -Encoding ascii -Force

        Write-Output "LAUNCHER_CREATED: `$batPath"
"@
    if (-not $step5.Success) { return $false }

    if ($step5.Output -match 'DOCM_DEPLOYED') {
        Write-Log '.docm test document deployed to C:\MDE-Demo\asr-tests\ASR-Test-OpenMe.docm' -Level SUCCESS
    }
    if ($step5.Output -match 'LAUNCHER_CREATED') {
        Write-Log 'One-click launcher deployed to C:\MDE-Demo\asr-tests\Run-AsrTest.bat' -Level SUCCESS
    }

    Write-Log 'Step 5/6: Verifying ASR rules are set...'
    $step6 = Invoke-DemoCommand -Description 'Verify ASR rule configuration' -ScriptContent @'
        $prefs = Get-MpPreference -ErrorAction Stop
        $ruleIds = $prefs.AttackSurfaceReductionRules_Ids
        $ruleActions = $prefs.AttackSurfaceReductionRules_Actions

        if ($ruleIds -and $ruleIds.Count -gt 0) {
            Write-Output "ASR rules in preferences: $($ruleIds.Count)"
            for ($i = 0; $i -lt $ruleIds.Count; $i++) {
                $action = $(if ($ruleActions[$i] -eq 1) { 'Block' }
                           elseif ($ruleActions[$i] -eq 2) { 'Audit' }
                           elseif ($ruleActions[$i] -eq 6) { 'Warn' }
                           else { "Unknown ($($ruleActions[$i]))" })
                Write-Output "  $($ruleIds[$i]) = $action"
            }
        }
        else {
            Write-Output 'Preferences: No ASR rules (Intune/GPO may manage via policy registry).'
        }

        # Also check policy registry (source of truth when Intune manages ASR)
        $rulesPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        if (Test-Path $rulesPolicyPath) {
            $policyRules = (Get-ItemProperty $rulesPolicyPath -ErrorAction SilentlyContinue).PSObject.Properties |
                Where-Object { $_.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider' }
            if ($policyRules) {
                Write-Output "ASR rules in policy registry: $($policyRules.Count)"
                foreach ($rule in $policyRules) {
                    $action = $(if ($rule.Value -eq '1') { 'Block' }
                               elseif ($rule.Value -eq '2') { 'Audit' }
                               elseif ($rule.Value -eq '6') { 'Warn' }
                               else { "Unknown ($($rule.Value))" })
                    Write-Output "  $($rule.Name) = $action (policy)"
                }
            }
        }

        # Check the Office child-process rule specifically (the interactive demo rule)
        $officeRuleId = 'D4F940AB-401B-4EfC-AADC-AD5F3C50688A'
        $prefActive = $ruleIds -and ($ruleIds -contains $officeRuleId)
        $policyActive = $false
        if (Test-Path $rulesPolicyPath) {
            $policyVal = (Get-ItemProperty $rulesPolicyPath -Name $officeRuleId -ErrorAction SilentlyContinue).$officeRuleId
            $policyActive = ($policyVal -eq '1')
        }

        if ($prefActive -or $policyActive) {
            Write-Output 'ASR_VERIFIED: Office child-process rule (D4F940AB) is active in Block mode.'
        }
        else {
            Write-Output 'ASR_NOT_VERIFIED: Office child-process rule (D4F940AB) could not be confirmed as active.'
        }
'@
    if (-not $step6.Success) { return $false }

    Write-Log 'Step 6/6: Setup complete.' -Level SUCCESS
    Write-Log 'ASR Rules simulation deployed.' -Level SUCCESS
    Write-Log '------------------------------------------------------------' -Level INFO
    Write-Log 'INTERACTIVE TEST (RDP required):' -Level WARN
    Write-Log '  1. RDP into the VM' -Level WARN
    Write-Log '  2. Double-click C:\MDE-Demo\asr-tests\Run-AsrTest.bat' -Level WARN
    Write-Log '  3. Word opens -- you will see a VBA error dialog:' -Level WARN
    Write-Log '     "Runtime Error 5: Invalid procedure call"' -Level WARN
    Write-Log '     This IS expected -- it proves ASR blocked cmd.exe' -Level WARN
    Write-Log '  4. Click OK to dismiss, then press Enter here to continue' -Level WARN
    Write-Log '     (the next screen shows the KQL query for verification)' -Level WARN
    Write-Log '------------------------------------------------------------' -Level INFO
    return $true
}
