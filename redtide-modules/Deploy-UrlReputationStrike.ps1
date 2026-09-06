<#
.SYNOPSIS
    Deploys the SmartScreen URL Reputation simulation to a target Azure VM.

.DESCRIPTION
    Verifies Defender AV is active on the VM and prints test URLs with
    expected results. This simulation requires Microsoft Edge on the VM desktop
    and cannot be fully automated -- the presenter must RDP in and navigate
    to each URL manually.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-UrlReputationStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log 'Step 1/3: Verifying Defender Antivirus is active on VM...'
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

    if ($step1.Output -match '^FAIL:.*not running') {
        Write-Log 'Defender AV is not running on the VM. Cannot proceed.' -Level ERROR
        return $false
    }

    Write-Log 'Step 2/3: Verifying Microsoft Edge is installed on VM...'
    $step2 = Invoke-DemoCommand -Description 'Check Microsoft Edge installation' -ScriptContent @'
        $edgePath = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
        if (-not (Test-Path $edgePath)) {
            $edgePath = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
        }
        if (Test-Path $edgePath) {
            $version = (Get-Item $edgePath).VersionInfo.ProductVersion
            Write-Output "OK: Microsoft Edge found (version $version)."
        }
        else {
            Write-Output 'WARN: Microsoft Edge was not found at the default path.'
        }
'@
    if (-not $step2.Success) { return $false }

    Write-Log 'Step 3/3: Printing test URLs and expected results...'
    Write-Log '----------------------------------------------------------------------'
    Write-Log 'SmartScreen URL Reputation -- Test URLs'
    Write-Log '----------------------------------------------------------------------'
    Write-Log '1. Is This Phishing? (suspicious page, asks for feedback)'
    Write-Log '   URL: https://nav.smartscreen.msft.net/other/areyousure.html'
    Write-Log ''
    Write-Log '2. Known Phishing Page (red block page)'
    Write-Log '   URL: https://nav.smartscreen.msft.net/phishingdemo.html'
    Write-Log ''
    Write-Log '3. Malware Page (red block page)'
    Write-Log '   URL: https://nav.smartscreen.msft.net/other/malware.html'
    Write-Log ''
    Write-Log '4. Blocked Download (download blocked by URL reputation)'
    Write-Log '   URL: https://nav.smartscreen.msft.net/download/malwaredemo/freevideo.exe'
    Write-Log ''
    Write-Log '5. Exploit Page (red block page)'
    Write-Log '   URL: https://demo.smartscreen.msft.net/other/exploit.html'
    Write-Log ''
    Write-Log '6. Malvertising (benign page hosting malicious ad iframe)'
    Write-Log '   URL: https://demo.smartscreen.msft.net/other/exploit_frame.html'
    Write-Log '----------------------------------------------------------------------'

    Write-Log 'SmartScreen URL Reputation simulation prerequisites verified.' -Level SUCCESS
    Write-Log 'NOTE: This simulation cannot be automated. You must RDP into the VM and open Microsoft Edge.' -Level WARN
    Write-Log 'Navigate to each URL above in Edge to demonstrate SmartScreen blocking.' -Level INFO
    return $true
}
