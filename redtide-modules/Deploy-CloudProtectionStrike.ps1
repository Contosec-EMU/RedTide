<#
.SYNOPSIS
    Deploys the Cloud-Delivered Protection simulation to a target Azure VM.

.DESCRIPTION
    Verifies Defender AV configuration and downloads the test file to C:\MDE-Demo\.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-CloudProtectionStrike {
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
            AMRunning         = $status.AMServiceEnabled
            RealTimeProtection = $status.RealTimeProtectionEnabled
            AntivirusEnabled  = $status.AntivirusEnabled
            CloudProtection   = $prefs.MAPSReporting
            SampleSubmission  = $prefs.SubmitSamplesConsent
        }

        if (-not $status.AMServiceEnabled) {
            Write-Output 'FAIL: Defender Antivirus service is not running.'
        }
        elseif (-not $status.RealTimeProtectionEnabled) {
            Write-Output 'FAIL: Real-time protection is disabled.'
        }
        elseif ($prefs.MAPSReporting -eq 0) {
            Write-Output 'FAIL: Cloud-delivered protection is disabled. Enabling...'
            Set-MpPreference -MAPSReporting Advanced
            Set-MpPreference -SubmitSamplesConsent SendAllSamples
            Write-Output 'Cloud-delivered protection enabled.'
        }
        else {
            Write-Output 'OK: Defender AV is active, real-time protection on, cloud protection on.'
        }

        Write-Output "MAPSReporting: $($prefs.MAPSReporting) | SampleConsent: $($prefs.SubmitSamplesConsent)"
'@
    if (-not $step2.Success) { return $false }

    if ($step2.Output -match '^FAIL:.*not running') {
        Write-Log 'Defender AV is not running on the VM. Cannot proceed.' -Level ERROR
        return $false
    }

    Write-Log 'Step 3/4: Downloading test file to VM...'
    $step3 = Invoke-DemoCommand -Description 'Download cloud protection test file' -ScriptContent @'
        $testFileUrl = 'https://go.microsoft.com/fwlink/?linkid=2298135'
        $destPath = 'C:\MDE-Demo\cloud-test-file.zip'

        # Temporarily allow download without being blocked
        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -Uri $testFileUrl -OutFile $destPath -UseBasicParsing -ErrorAction Stop
            Write-Output "Downloaded test file to $destPath"
            Write-Output "File size: $((Get-Item $destPath).Length) bytes"
        }
        catch {
            Write-Output "WARN: Could not download test file: $_"
            Write-Output "Manual download needed: $testFileUrl (password: infected)"
        }
'@
    if (-not $step3.Success) { return $false }

    Write-Log 'Step 4/4: Verifying setup...'
    $step4 = Invoke-DemoCommand -Description 'Verify simulation files' -ScriptContent @'
        $files = Get-ChildItem -Path 'C:\MDE-Demo' -ErrorAction SilentlyContinue
        Write-Output "Files in C:\MDE-Demo:"
        foreach ($f in $files) {
            Write-Output "  $($f.Name) ($($f.Length) bytes)"
        }
'@

    Write-Log 'Cloud-Delivered Protection simulation deployed.' -Level SUCCESS
    Write-Log 'NOTE: Test file is a password-protected ZIP (password: infected).' -Level WARN
    Write-Log 'During the simulation, extract and run the file to trigger detection.' -Level INFO
    return $true
}
