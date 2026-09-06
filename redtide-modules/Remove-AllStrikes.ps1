<#
.SYNOPSIS
    Cleans up all MDE simulation artifacts from the target Azure VM.

.DESCRIPTION
    Restores the VM to its pre-simulation state in a single Run Command call:
      - Restores Defender settings from baseline (captured before simulations)
      - Restores Exploit Protection from backup
      - Clears quarantined threats
      - Removes simulation directories
    Uses a single Invoke-DemoCommand call to minimize Defender alert noise.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Remove-AllStrikes {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log 'Restoring system to baseline configuration...'

    $cleanupResult = Invoke-DemoCommand -Description 'Restoring system configuration and removing simulation artifacts' -ScriptContent @'
        $warnings = @()

        # ---- Restore Defender settings from baseline ----
        $baselineFile = 'C:\MDE-Demo\baseline-state.json'
        if (Test-Path $baselineFile) {
            try {
                $baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json

                # Restore CFA
                if ($null -ne $baseline.CFA) {
                    Set-MpPreference -EnableControlledFolderAccess $baseline.CFA -ErrorAction SilentlyContinue
                    Write-Output "CFA restored to: $($baseline.CFA)"
                }

                # Restore CFA policy registry key if it was captured
                if ($null -ne $baseline.CFA_Policy) {
                    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
                    if (Test-Path $policyPath) {
                        Set-ItemProperty $policyPath -Name EnableControlledFolderAccess -Value $baseline.CFA_Policy -ErrorAction SilentlyContinue
                        Write-Output "CFA policy key restored to: $($baseline.CFA_Policy)"
                    }
                }

                # Remove C:\demo\ from policy ProtectedFolders registry if we added it
                $foldersPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\ProtectedFolders'
                if (Test-Path $foldersPolicyPath) {
                    $prop = Get-ItemProperty $foldersPolicyPath -Name 'C:\demo\' -ErrorAction SilentlyContinue
                    if ($null -ne $prop.'C:\demo\') {
                        Remove-ItemProperty -Path $foldersPolicyPath -Name 'C:\demo\' -ErrorAction SilentlyContinue
                        Write-Output "Removed C:\demo\ from policy ProtectedFolders registry"
                    }
                }

                # Remove PowerShell from CFA AllowedApplications policy registry
                $appsPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications'
                if (Test-Path $appsPolicyPath) {
                    $psPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                    Remove-ItemProperty -Path $appsPolicyPath -Name $psPath -ErrorAction SilentlyContinue
                }

                # Remove AV exclusion for ransomware test exe
                $exclPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths'
                if (Test-Path $exclPolicyPath) {
                    Remove-ItemProperty -Path $exclPolicyPath -Name 'C:\MDE-Demo\ransomware_testfile.exe' -ErrorAction SilentlyContinue
                }
                Remove-MpPreference -ExclusionPath 'C:\MDE-Demo\ransomware_testfile.exe' -ErrorAction SilentlyContinue

                # Restore Network Protection
                if ($null -ne $baseline.NetworkProtection) {
                    Set-MpPreference -EnableNetworkProtection $baseline.NetworkProtection -ErrorAction SilentlyContinue
                    Write-Output "Network Protection restored to: $($baseline.NetworkProtection)"
                }

                # Restore PUA Protection
                if ($null -ne $baseline.PUAProtection) {
                    Set-MpPreference -PUAProtection $baseline.PUAProtection -ErrorAction SilentlyContinue
                    Write-Output "PUA Protection restored to: $($baseline.PUAProtection)"
                }

                # Restore MAPS Reporting
                if ($null -ne $baseline.MAPSReporting) {
                    Set-MpPreference -MAPSReporting $baseline.MAPSReporting -ErrorAction SilentlyContinue
                    Write-Output "MAPS Reporting restored to: $($baseline.MAPSReporting)"
                }

                # Restore Sample Submission
                if ($null -ne $baseline.SubmitSamples) {
                    Set-MpPreference -SubmitSamplesConsent $baseline.SubmitSamples -ErrorAction SilentlyContinue
                }

                # Restore Behavior Monitoring
                if ($null -ne $baseline.BehaviorMonitoring) {
                    Set-MpPreference -DisableBehaviorMonitoring $baseline.BehaviorMonitoring -ErrorAction SilentlyContinue
                }

                # Restore CFA protected folders -- remove any that were not in baseline
                $currentFolders = @((Get-MpPreference).ControlledFolderAccessProtectedFolders)
                $baselineFolders = @($baseline.CFAFolders)
                if ($currentFolders) {
                    $added = $currentFolders | Where-Object { $_ -and $_ -notin $baselineFolders }
                    if ($added) {
                        $keepFolders = $currentFolders | Where-Object { $_ -in $baselineFolders }
                        if ($keepFolders) {
                            Set-MpPreference -ControlledFolderAccessProtectedFolders $keepFolders -ErrorAction SilentlyContinue
                        }
                        Write-Output "Removed simulation-added CFA folders"
                    }
                }

                # Restore ASR rules to baseline state
                $simRules = @(
                    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
                    'D4F940AB-401B-4EfC-AADC-AD5F3C50688A'
                    '3B576869-A4EC-4529-8536-B80A7769E899'
                    'D3E037E1-3EB8-44C8-A917-57927947596D'
                    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
                    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
                    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'
                    'C1DB55AB-C21A-4637-BB3F-A12568109D35'
                )
                $baselineIds = @($baseline.ASR_Ids)
                $baselineActions = @($baseline.ASR_Actions)

                foreach ($ruleId in $simRules) {
                    $idx = if ($baselineIds) { [array]::IndexOf($baselineIds, $ruleId) } else { -1 }
                    if ($idx -ge 0) {
                        $originalAction = $baselineActions[$idx]
                        Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId `
                            -AttackSurfaceReductionRules_Actions $originalAction -ErrorAction SilentlyContinue
                    }
                    else {
                        Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId `
                            -AttackSurfaceReductionRules_Actions 0 -ErrorAction SilentlyContinue
                    }
                }
                Write-Output "ASR rules restored to baseline"

            }
            catch {
                $warnings += "Could not fully restore from baseline: $_"
                Write-Output "WARN: Baseline restore error: $_"
            }
        }
        else {
            Write-Output "WARN: No baseline file found. Using safe defaults."

            # Fallback: disable features that simulations may have enabled
            Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
            Set-MpPreference -EnableNetworkProtection Disabled -ErrorAction SilentlyContinue
            Set-MpPreference -PUAProtection Disabled -ErrorAction SilentlyContinue
            $simRules = @(
                'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550', 'D4F940AB-401B-4EfC-AADC-AD5F3C50688A',
                '3B576869-A4EC-4529-8536-B80A7769E899', 'D3E037E1-3EB8-44C8-A917-57927947596D',
                '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC', '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',
                'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4', 'C1DB55AB-C21A-4637-BB3F-A12568109D35'
            )
            foreach ($ruleId in $simRules) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId `
                    -AttackSurfaceReductionRules_Actions 0 -ErrorAction SilentlyContinue
            }
            Write-Output "Settings reset to safe defaults"
        }

        # ---- Restore Exploit Protection from backup ----
        $backupPath = 'C:\MDE-Demo\EP-backup.xml'
        if (Test-Path $backupPath) {
            try {
                Set-ProcessMitigation -PolicyFilePath $backupPath -ErrorAction Stop
                Write-Output "Exploit Protection restored from backup"
            }
            catch {
                $warnings += "Could not restore Exploit Protection: $_"
                Write-Output "WARN: Exploit Protection restore failed: $_"
            }
        }

        # ---- Clear quarantined threats ----
        try {
            $threats = Get-MpThreat -ErrorAction SilentlyContinue
            if ($threats) {
                Remove-MpThreat -ErrorAction SilentlyContinue
                Write-Output "Cleared $($threats.Count) quarantined threat(s)"
            }
            else {
                Write-Output "No quarantined threats found"
            }
        }
        catch {
            $warnings += "Could not clear quarantined threats: $_"
        }

        # ---- Ensure CFA is fully disabled before removing protected folders ----
        try {
            Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
            $cfaPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
            if (Test-Path $cfaPolicyPath) {
                Set-ItemProperty $cfaPolicyPath -Name EnableControlledFolderAccess -Value 0 -ErrorAction SilentlyContinue
            }
            Start-Sleep -Seconds 2
        } catch { }

        # ---- Remove simulation directories ----
        @('C:\MDE-Demo', 'C:\demo') | ForEach-Object {
            if (Test-Path $_) {
                try {
                    Remove-Item -Path $_ -Recurse -Force -ErrorAction Stop
                    Write-Output "Removed: $_"
                }
                catch {
                    $warnings += "Could not remove $_`: $($_.Exception.Message)"
                    Write-Output "WARN: Could not remove $_`: $($_.Exception.Message)"
                }
            }
        }

        # ---- Final status ----
        if ($warnings.Count -eq 0) {
            Write-Output "CLEANUP_STATUS:SUCCESS"
        }
        else {
            Write-Output "CLEANUP_STATUS:PARTIAL"
            foreach ($w in $warnings) { Write-Output "CLEANUP_WARN:$w" }
        }
'@

    if (-not $cleanupResult.Success) {
        Write-Log 'Cleanup failed to execute on VM.' -Level ERROR
        return $false
    }

    $output = $cleanupResult.Output
    if ($output -match 'CLEANUP_STATUS:SUCCESS') {
        Write-Log 'System restored to baseline configuration.' -Level SUCCESS
        return $true
    }
    elseif ($output -match 'CLEANUP_STATUS:PARTIAL') {
        Write-Log 'Cleanup completed with warnings. Some settings may need manual review.' -Level WARN
        return $true
    }
    else {
        Write-Log 'Cleanup returned unexpected output.' -Level WARN
        return $false
    }
}
