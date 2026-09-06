<#
.SYNOPSIS
    Deploys the Controlled Folder Access (ransomware) simulation to a target Azure VM.

.DESCRIPTION
    Creates a protected folder with test documents, enables CFA, downloads the
    ransomware test file, and executes it to trigger a CFA block alert.
    The test exe has a hardcoded target of C:\demo, so documents go there.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-ControlledFolderStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # The ransomware test file from demo.wd.microsoft.com targets C:\demo
    # (hardcoded in the exe). Documents must be in that path for the test to work.

    Write-Log 'Step 1/6: Creating C:\demo with test documents...'
    $step1 = Invoke-DemoCommand -Description 'Create C:\demo folder with test docs' -ScriptContent @'
        # CFA may already be active (Intune policy or previous run). Temporarily allow
        # PowerShell to write to the protected folder so we can create test documents.
        $psPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $cfaApps = @((Get-MpPreference).ControlledFolderAccessAllowedApplications)
        $psWasAllowed = $cfaApps -contains $psPath
        if (-not $psWasAllowed) {
            Add-MpPreference -ControlledFolderAccessAllowedApplications $psPath -ErrorAction SilentlyContinue
            # Also add via policy registry in case Intune manages CFA
            $appsPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications'
            if (-not (Test-Path $appsPolicyPath)) {
                New-Item -Path $appsPolicyPath -Force | Out-Null
            }
            New-ItemProperty -Path $appsPolicyPath -Name $psPath -Value 0 -PropertyType DWord -Force | Out-Null
            Start-Sleep -Seconds 2
        }

        New-Item -ItemType Directory -Path 'C:\demo' -Force | Out-Null

        # Create sample business documents that the test file will try to encrypt
        'Q4 Financial Report - Confidential' | Out-File -FilePath 'C:\demo\Q4-Financial-Report.txt' -Encoding utf8
        'Employee Records - HR Department' | Out-File -FilePath 'C:\demo\Employee-Records.txt' -Encoding utf8
        'Board Meeting Notes - Draft' | Out-File -FilePath 'C:\demo\Board-Meeting-Notes.txt' -Encoding utf8

        # Remove PowerShell from allowed apps so CFA blocks the ransomware exe later
        if (-not $psWasAllowed) {
            Remove-MpPreference -ControlledFolderAccessAllowedApplications $psPath -ErrorAction SilentlyContinue
            $appsPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications'
            if (Test-Path $appsPolicyPath) {
                Remove-ItemProperty -Path $appsPolicyPath -Name $psPath -ErrorAction SilentlyContinue
            }
        }

        $count = (Get-ChildItem 'C:\demo').Count
        Write-Output "Created C:\demo with $count files."
'@
    if (-not $step1.Success) { return $false }

    Write-Log 'Step 2/6: Checking Aggressive Ransomware Prevention ASR rule...'
    $step2 = Invoke-DemoCommand -Description 'Check ASR rule status' -ScriptContent @'
        $ruleId = 'C1DB55AB-C21A-4637-BB3F-A12568109D35'
        $ids = (Get-MpPreference).AttackSurfaceReductionRules_Ids
        $actions = (Get-MpPreference).AttackSurfaceReductionRules_Actions

        if ($ids) {
            $idx = [array]::IndexOf($ids, $ruleId)
        } else {
            $idx = -1
        }

        if ($idx -ge 0) {
            $status = $actions[$idx]
            Write-Output "ASR_RULE_STATUS:$status"
            if ($status -eq 1 -or $status -eq 6) {
                Write-Output "Disabling Aggressive Ransomware ASR rule for simulation..."
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Disabled
                Write-Output "ASR rule disabled. Will need re-enabling after simulation."
            } else {
                Write-Output "ASR rule already disabled or in audit mode."
            }
        } else {
            Write-Output "ASR_RULE_STATUS:NOT_FOUND"
            Write-Output "Aggressive Ransomware ASR rule not configured on this VM."
        }
'@
    if (-not $step2.Success) { return $false }

    Write-Log 'Step 3/6: Enabling Controlled Folder Access (block mode)...'
    $step3 = Invoke-DemoCommand -Description 'Enable CFA and protect C:\demo' -ScriptContent @'
        # When Intune/GPO manages CFA, Set-MpPreference is silently ignored for ALL
        # CFA settings (mode AND folder list). We must set both via the policy registry.
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
        $foldersPolicyPath = "$policyPath\ProtectedFolders"
        $policyManaged = $false

        # --- Override CFA mode via policy registry ---
        if (Test-Path $policyPath) {
            $policyVal = (Get-ItemProperty $policyPath -Name EnableControlledFolderAccess -ErrorAction SilentlyContinue).EnableControlledFolderAccess
            if ($null -ne $policyVal) {
                $policyManaged = $true
                if ($policyVal -ne 1) {
                    Write-Output "POLICY_OVERRIDE: Intune/GPO policy key is $policyVal (not block). Overriding to 1 (block)."
                    Set-ItemProperty $policyPath -Name EnableControlledFolderAccess -Value 1
                } else {
                    Write-Output "Policy key already set to block mode."
                }
            }
        }

        # --- Override protected folders via policy registry ---
        # When policy manages CFA, Set-MpPreference for folders is ignored.
        if ($policyManaged) {
            if (-not (Test-Path $foldersPolicyPath)) {
                New-Item -Path $foldersPolicyPath -Force | Out-Null
                Write-Output "Created policy ProtectedFolders registry key."
            }
            # Save existing folder entries before adding ours
            $existingEntries = Get-ItemProperty $foldersPolicyPath -ErrorAction SilentlyContinue
            $hasDemo = $false
            if ($existingEntries) {
                $existingEntries.PSObject.Properties | Where-Object {
                    $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
                } | ForEach-Object {
                    if ($_.Name -eq 'C:\demo\') { $hasDemo = $true }
                }
            }
            if (-not $hasDemo) {
                New-ItemProperty -Path $foldersPolicyPath -Name 'C:\demo\' -Value 0 -PropertyType DWord -Force | Out-Null
                Write-Output "Added C:\demo\ to policy ProtectedFolders registry."
            } else {
                Write-Output "C:\demo\ already in policy ProtectedFolders registry."
            }
        }

        # Also set via Set-MpPreference (works when no policy manages CFA)
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -ControlledFolderAccessProtectedFolders 'C:\demo\' -ErrorAction SilentlyContinue

        # Wait for Defender to pick up registry changes
        Start-Sleep -Seconds 5

        # Verify effective state
        $cfa = (Get-MpPreference).EnableControlledFolderAccess
        $folders = @((Get-MpPreference).ControlledFolderAccessProtectedFolders)

        $effectivePolicy = $null
        if (Test-Path $policyPath) {
            $effectivePolicy = (Get-ItemProperty $policyPath -Name EnableControlledFolderAccess -ErrorAction SilentlyContinue).EnableControlledFolderAccess
        }

        # Check policy registry for protected folders
        $policyFolders = @()
        if (Test-Path $foldersPolicyPath) {
            (Get-ItemProperty $foldersPolicyPath -ErrorAction SilentlyContinue).PSObject.Properties |
                Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
                ForEach-Object { $policyFolders += $_.Name }
        }

        Write-Output "CFA local pref: $cfa"
        Write-Output "CFA policy key: $effectivePolicy"
        Write-Output "Protected folders (local): $($folders -join ', ')"
        Write-Output "Protected folders (policy): $($policyFolders -join ', ')"

        if ($effectivePolicy -eq 1 -or ($null -eq $effectivePolicy -and $cfa -eq 1)) {
            Write-Output "CFA_BLOCK_MODE: Active"
        } else {
            Write-Output "CFA_NOT_BLOCK: Policy key is $effectivePolicy -- block mode could not be set"
        }

        $allFolders = @($folders) + @($policyFolders) | Select-Object -Unique
        $demoProtected = $allFolders | Where-Object { $_ -eq 'C:\demo\' -or $_ -eq 'C:\demo' }
        if (-not $demoProtected) {
            Write-Output "CFA_NO_FOLDER: C:\demo not in any protected folders list"
        }
'@
    if (-not $step3.Success) { return $false }

    if ($step3.Output -match 'POLICY_OVERRIDE') {
        Write-Log 'Intune/GPO was forcing CFA to audit mode. Overrode policy to block mode for this demo.' -Level WARN
    }
    if ($step3.Output -match 'CFA_NOT_BLOCK') {
        Write-Log 'Could not set CFA to block mode. The simulation may not generate an alert.' -Level ERROR
    }
    if ($step3.Output -match 'CFA_NO_FOLDER') {
        Write-Log 'C:\demo is not in any protected folders list. CFA will not protect it.' -Level ERROR
    }

    Write-Log 'Step 4/6: Downloading ransomware test file...'
    $step4 = Invoke-DemoCommand -Description 'Download ransomware test file' -ScriptContent @'
        New-Item -ItemType Directory -Path 'C:\MDE-Demo' -Force | Out-Null

        # Add AV exclusion for the test exe path to prevent CustomEnterpriseBlock
        # from quarantining it before CFA can act. Also set via policy registry.
        $exePath = 'C:\MDE-Demo\ransomware_testfile.exe'
        Add-MpPreference -ExclusionPath $exePath -ErrorAction SilentlyContinue
        $exclPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths'
        if (-not (Test-Path $exclPolicyPath)) {
            New-Item -Path $exclPolicyPath -Force | Out-Null
        }
        New-ItemProperty -Path $exclPolicyPath -Name $exePath -Value 0 -PropertyType DWord -Force | Out-Null
        Start-Sleep -Seconds 2

        $testFileUrl = 'https://demo.wd.microsoft.com/Content/ransomware_testfile_unsigned.exe'
        $destPath = $exePath

        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -Uri $testFileUrl -OutFile $destPath -UseBasicParsing -ErrorAction Stop
            Write-Output "Downloaded ransomware test file to $destPath"
            Write-Output "File size: $((Get-Item $destPath).Length) bytes"
        }
        catch {
            Write-Output "WARN: Could not download test file: $_"
            Write-Output "Manual download needed from: $testFileUrl"
        }
'@
    if (-not $step4.Success) { return $false }

    Write-Log 'Step 5/6: Running ransomware test file (targets C:\demo)...'
    $step5 = Invoke-DemoCommand -Description 'Execute ransomware test file' -ExpectErrors -ScriptContent @'
        $exePath = 'C:\MDE-Demo\ransomware_testfile.exe'
        if (-not (Test-Path $exePath)) {
            Write-Output 'FAIL: ransomware_testfile.exe not found.'
            exit 1
        }

        # Redirect stdout/stderr to files. The test exe writes raw bytes to its
        # console which, when running inside a Start-Job host, pollute the CLIXML
        # pipe back to the parent and cause Receive-Job to throw
        # "Cannot process an element with node type Text". Redirecting keeps the
        # bytes off the host channel entirely.
        $exeStdOut = 'C:\MDE-Demo\ransomware_testfile.out.log'
        $exeStdErr = 'C:\MDE-Demo\ransomware_testfile.err.log'
        try {
            Start-Process -FilePath $exePath -Wait -NoNewWindow `
                -RedirectStandardOutput $exeStdOut `
                -RedirectStandardError $exeStdErr `
                -ErrorAction Stop
        }
        catch {
            # Expected -- CFA or Defender may terminate the process
        }

        Start-Sleep -Seconds 5

        # Check whether CFA blocked the attempt by looking for original filenames.
        # If encrypted, files become .encrypted! and help_decrypt.* files appear.
        $encrypted = Get-ChildItem 'C:\demo' -Filter '*.encrypted!' -ErrorAction SilentlyContinue
        $originals = @(
            'C:\demo\Q4-Financial-Report.txt',
            'C:\demo\Employee-Records.txt',
            'C:\demo\Board-Meeting-Notes.txt'
        )
        $intactCount = ($originals | Where-Object { Test-Path $_ }).Count

        Write-Output "Original files intact: $intactCount/3"
        Write-Output "Encrypted files found: $($encrypted.Count)"

        if ($intactCount -eq 3 -and $encrypted.Count -eq 0) {
            Write-Output "CFA_BLOCKED: Files are intact -- CFA blocked the encryption attempt."
        } else {
            Write-Output "CFA_NOT_BLOCKED: Files were encrypted -- CFA did not block the attempt."
        }
'@
    if (-not $step5.Success) { return $false }

    if ($step5.Output -match 'CFA_NOT_BLOCKED') {
        Write-Log 'CFA may not have blocked the ransomware test file. Verify CFA is enabled.' -Level WARN
    }
    elseif ($step5.Output -match 'CFA_BLOCKED') {
        Write-Log 'CFA blocked the encryption attempt -- files are intact.' -Level SUCCESS
    }

    Write-Log 'Step 6/6: Verifying final state...'
    $step6 = Invoke-DemoCommand -Description 'Verify CFA simulation setup' -ScriptContent @'
        Write-Output "=== CFA Simulation Status ==="
        Write-Output "CFA Enabled: $((Get-MpPreference).EnableControlledFolderAccess)"
        Write-Output ""
        Write-Output "Protected folder (C:\demo) contents:"
        Get-ChildItem 'C:\demo' | ForEach-Object {
            Write-Output "  $($_.Name) ($($_.Length) bytes)"
        }
        Write-Output ""
        Write-Output "Test file:"
        if (Test-Path 'C:\MDE-Demo\ransomware_testfile.exe') {
            Write-Output "  C:\MDE-Demo\ransomware_testfile.exe (present)"
        } else {
            Write-Output "  NOT FOUND -- may have been quarantined"
        }
'@

    Write-Log 'Controlled Folder Access simulation complete.' -Level SUCCESS
    Write-Log 'NOTE: The test file is NOT actual ransomware -- it safely simulates encryption.' -Level WARN
    return $true
}
