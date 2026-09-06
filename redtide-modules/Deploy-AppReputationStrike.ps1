<#
.SYNOPSIS
    Deploys the SmartScreen App Reputation simulation to a target Azure VM.

.DESCRIPTION
    Verifies Defender AV is active and prints manual simulation instructions.
    This simulation requires Microsoft Edge on the VM and cannot be fully automated.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-AppReputationStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log 'Step 1/2: Verifying Defender Antivirus is active on VM...'
    $step1 = Invoke-DemoCommand -Description 'Check Defender AV status' -ScriptContent @'
        $status = Get-MpComputerStatus -ErrorAction Stop

        if (-not $status.AMServiceEnabled) {
            Write-Output 'FAIL: Defender Antivirus service is not running.'
        }
        elseif (-not $status.RealTimeProtectionEnabled) {
            Write-Output 'FAIL: Real-time protection is disabled.'
        }
        elseif (-not $status.AntivirusEnabled) {
            Write-Output 'FAIL: Antivirus is not enabled.'
        }
        else {
            Write-Output 'OK: Defender AV is active and real-time protection is on.'
        }
'@
    if (-not $step1.Success) { return $false }

    if ($step1.Output -match '^FAIL:') {
        Write-Log 'Defender AV is not healthy on the VM. Cannot proceed.' -Level ERROR
        return $false
    }

    Write-Log 'Step 2/2: Printing simulation instructions...'
    Write-Log '----------------------------------------------------------------------'
    Write-Log 'SmartScreen App Reputation -- Manual Steps Required' -Level WARN
    Write-Log '----------------------------------------------------------------------'
    Write-Log 'This simulation REQUIRES Microsoft Edge on the VM desktop (RDP or Bastion).'
    Write-Log 'Open Edge and go to: https://demo.smartscreen.msft.net'
    Write-Log 'Scroll down to the "App Rep Demos" section, then test each:'
    Write-Log ''
    Write-Log '  TEST 1: Known Good Program'
    Write-Log '    Click the green "Known Good Program" card to download freevideo.exe'
    Write-Log '    Open the downloaded file and run it'
    Write-Log '    EXPECTED: Runs normally with message "established reputation"'
    Write-Log ''
    Write-Log '  TEST 2: Unknown Program'
    Write-Log '    Click the yellow "Unknown Program" card to download freevideo.exe'
    Write-Log '    Open the downloaded file and run it'
    Write-Log '    EXPECTED: SmartScreen warning "freevideo.exe isn''t commonly downloaded"'
    Write-Log ''
    Write-Log '  TEST 3: Known Malware'
    Write-Log '    Click the red "Known Malware" card to download knownmalicious.exe'
    Write-Log '    Open the downloaded file and try to run it'
    Write-Log '    EXPECTED: "knownmalicious.exe was blocked as unsafe by Microsoft Defender SmartScreen"'
    Write-Log ''
    Write-Log '----------------------------------------------------------------------'

    Write-Log 'App Reputation simulation prerequisites verified.' -Level SUCCESS
    Write-Log 'NOTE: You must RDP into the VM and use Microsoft Edge for this simulation.' -Level WARN
    return $true
}
