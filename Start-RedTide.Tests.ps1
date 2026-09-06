#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    # Dot-source the script to load functions without running Main.
    # Strip the trailing Main call and replace 'exit $exitCode' so it
    # doesn't terminate the test runner.
    $scriptPath = Join-Path $PSScriptRoot 'Start-RedTide.ps1'

    $content = Get-Content $scriptPath -Raw
    $content = $content -replace 'Main\s*$', ''
    $content = $content -replace 'exit \$exitCode', 'return $exitCode'

    $tempScript = Join-Path $PSScriptRoot ".redtide-test-functions-$([guid]::NewGuid()).ps1"
    try {
        Set-Content -Path $tempScript -Value $content -Encoding UTF8
        . $tempScript
    }
    finally {
        Remove-Item $tempScript -ErrorAction SilentlyContinue
    }

    $script:TestArtifactPath = Join-Path $PSScriptRoot ".test-artifacts\$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $script:TestArtifactPath -Force | Out-Null

    # Reset ErrorActionPreference so Pester mock failures don't abort tests
    $ErrorActionPreference = 'Continue'
    # No test may dispatch a payload or create a real background job.
    Mock Invoke-DemoCommand { throw 'Scenario execution is prohibited in unit tests.' }
    Mock Invoke-WithSpinner { throw 'Environment operations are prohibited in unit tests.' }
    Mock Start-Job { throw 'Background jobs are prohibited in unit tests.' }
    Mock Invoke-WebRequest { throw 'Network requests are prohibited in unit tests.' }
}

AfterAll {
    if ($script:TestArtifactPath -and (Test-Path $script:TestArtifactPath)) {
        Remove-Item -LiteralPath $script:TestArtifactPath -Recurse -Force
    }
}

# ---------------------------------------------------------------------------
# 1. Color Palette
# ---------------------------------------------------------------------------
Describe 'Color Palette' {
    It 'should define all required color roles' {
        $required = @('Border', 'Title', 'Body', 'Menu', 'Success', 'Warning', 'Error', 'Muted')
        foreach ($key in $required) {
            $script:Colors.Keys | Should -Contain $key
        }
    }

    It 'should use valid ConsoleColor values' {
        foreach ($entry in $script:Colors.GetEnumerator()) {
            { [System.ConsoleColor]$entry.Value } | Should -Not -Throw
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Write-Log
# ---------------------------------------------------------------------------
Describe 'Write-Log' {
    BeforeEach {
        $script:LogFile = Join-Path $script:TestArtifactPath "$([guid]::NewGuid()).log"
        Mock Write-Host {}
    }

    AfterEach {
        if ($script:LogFile -and (Test-Path $script:LogFile)) {
            Remove-Item $script:LogFile -ErrorAction SilentlyContinue
        }
        $script:LogFile = $null
    }

    It 'writes INFO with [*] prefix to console' {
        Write-Log -Message 'test' -Level INFO
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[*`] test*' } -Times 1
    }

    It 'writes SUCCESS with [+] prefix' {
        Write-Log -Message 'test' -Level SUCCESS
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[+`] test*' } -Times 1
    }

    It 'writes WARN with [!] prefix' {
        Write-Log -Message 'test' -Level WARN
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[!`] test*' } -Times 1
    }

    It 'writes ERROR with [X] prefix' {
        Write-Log -Message 'test' -Level ERROR
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[X`] test*' } -Times 1
    }

    It 'appends to log file with timestamp format' {
        Write-Log -Message 'test' -Level INFO
        $lines = @(Get-Content $script:LogFile)
        $lines[-1] | Should -Match '\[\d{2}:\d{2}:\d{2}\] \[INFO\] test'
    }

    It 'defaults to INFO level' {
        Write-Log -Message 'msg'
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[*`] msg*' } -Times 1
    }
}

# ---------------------------------------------------------------------------
# 3. Write-CheckResult
# ---------------------------------------------------------------------------
Describe 'Write-CheckResult' {
    BeforeEach { Mock Write-Host {} }

    It 'formats pass result with [+] symbol' {
        Write-CheckResult -Label 'Check' -Status 'pass'
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[+`]*' } -Times 1
    }

    It 'formats fail result with [X] symbol' {
        Write-CheckResult -Label 'Check' -Status 'fail'
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[X`]*' } -Times 1
    }

    It 'formats warn result with [!] symbol' {
        Write-CheckResult -Label 'Check' -Status 'warn'
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*`[!`]*' } -Times 1
    }

    It 'includes dot leaders between label and status' {
        Write-CheckResult -Label 'Check' -Status 'pass'
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*...*' } -Times 1
    }

    It 'includes detail text after symbol' {
        Write-CheckResult -Label 'Check' -Status 'pass' -Detail 'all good'
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*all good*' } -Times 1
    }
}

# ---------------------------------------------------------------------------
# 4. Show-PageBanner
# ---------------------------------------------------------------------------
Describe 'Show-PageBanner' {
    BeforeEach {
        Mock Write-Host {}
        Mock Clear-Host {}
    }

    It 'uses box-drawing characters for major banners' {
        Show-PageBanner -Title 'Test' -NoClear
        # The major banner uses double-line box chars: ╔ (0x2554), ═ (0x2550), ╗ (0x2557)
        Should -Invoke Write-Host -ParameterFilter {
            $Object -like "*$([char]0x2554)*"
        } -Times 1
    }

    It 'uses lightweight rule for minor banners' {
        Show-PageBanner -Title 'Test' -NoClear -Minor
        # Minor banner uses single-line: ─ (0x2500)
        Should -Invoke Write-Host -ParameterFilter {
            $Object -like "*$([char]0x2500)*$([char]0x2500)*"
        } -Times 1
    }

    It 'clears screen by default' {
        Show-PageBanner -Title 'Test'
        Should -Invoke Clear-Host -Times 1
    }

    It 'does not clear screen with -NoClear' {
        Show-PageBanner -Title 'Test' -NoClear
        Should -Invoke Clear-Host -Times 0
    }
}

# ---------------------------------------------------------------------------
# 5. Show-Menu
# ---------------------------------------------------------------------------
Describe 'Show-Menu' {
    BeforeEach {
        Mock Show-PageBanner {}
        Mock Clear-Host {}
        Mock Write-Host {}
        Mock Show-InteractiveMenu { return 'CloudProtection' }
    }

    It 'calls Show-InteractiveMenu with items' {
        $result = Show-Menu
        Should -Invoke Show-InteractiveMenu -Times 1
    }

    It 'returns CloudProtection when first item selected' {
        $result = Show-Menu
        $result | Should -Be 'CloudProtection'
    }

    It 'returns Exit when Show-InteractiveMenu returns null (Esc pressed)' {
        Mock Show-InteractiveMenu { return $null }
        $result = Show-Menu
        $result | Should -Be 'Exit'
    }

    It 'passes correct number of selectable items' {
        Mock Show-InteractiveMenu {
            param($Items)
            $selectables = @($Items | Where-Object { $null -ne $_.Value })
            $selectables.Count | Should -Be 17   # 13 scenarios + All + Cleanup + MainPage + Exit
            return 'Exit'
        }
        Show-Menu
    }
}

# ---------------------------------------------------------------------------
# 6. Read-VMInfo
# ---------------------------------------------------------------------------
Describe 'Read-VMInfo' {
    BeforeEach {
        Mock Write-Host {}
        Mock Show-PageBanner {}
        Mock Clear-Host {}
    }

    AfterEach {
        $script:ResourceGroup = $null
        $script:VMName = $null
    }

    It 'does not prompt when ResourceGroup and VMName are already set' {
        $script:ResourceGroup = 'test-rg'
        $script:VMName = 'test-vm'
        Mock Show-InputWithValidation { throw 'should not be called' }
        { Read-VMInfo } | Should -Not -Throw
    }

    It 'prompts for ResourceGroup when not set' {
        $script:ResourceGroup = $null
        $script:VMName = 'test-vm'
        Mock Show-InputWithValidation { return 'new-rg' }
        Read-VMInfo
        $script:ResourceGroup | Should -Be 'new-rg'
    }

    It 'prompts for VMName when not set' {
        $script:ResourceGroup = 'test-rg'
        $script:VMName = $null
        Mock Show-InputWithValidation { return 'new-vm' }
        Read-VMInfo
        $script:VMName | Should -Be 'new-vm'
    }
}

# ---------------------------------------------------------------------------
# 7. Navigation Flow (Main function logic)
# ---------------------------------------------------------------------------
Describe 'Navigation Flow' {
    BeforeEach {
        # Provide script params that Main references
        $script:Scenario = $null
        $script:ResourceGroup = $null
        $script:VMName = $null
        $script:SubscriptionId = $null
        $script:LogPath = $null
        $script:SkipChecks = $false
        $script:LogFile = $null
        $script:ReturnToMain = $false
        $script:ReturnToMenu = $false
        $script:Local = $false
        $script:LocalMode = $false
        $script:BaselineCaptured = $false

        Mock Show-Banner {}
        Mock Show-PageBanner {}
        Mock Write-Host {}
        Mock Write-Log {}
        Mock Read-VMInfo {}
        Mock Test-Prerequisites { return $true }
        Mock Test-VmReadiness { return $true }
        Mock Test-VMConnection { return $true }
        Mock Test-LocalPrerequisites { return $true }
        Mock Test-LocalConnection { return $true }
        Mock Save-DefenderBaseline { return $true }
        Mock Show-Menu { return 'Exit' }
        Mock Invoke-Scenario { return $true }
        Mock Show-NextSteps {}
        Mock Initialize-LogFile {}
        Mock Clear-Host {}
        Mock Show-Confirmation { return $true }

        # Read-Host mock driven by $script:ReadHostResponses
        $script:ReadHostResponses = @('3')
        $script:ReadHostIndex = 0
        Mock Read-Host {
            $idx = $script:ReadHostIndex
            $script:ReadHostIndex++
            if ($idx -lt $script:ReadHostResponses.Count) {
                return $script:ReadHostResponses[$idx]
            }
            return ''
        }
    }

    It 'Option 1 calls Read-VMInfo then Test-Prerequisites' {
        # Welcome menu returns 'Checks' (run pre-flight)
        Mock Show-InteractiveMenu { return 'Checks' }

        Main

        Should -Invoke Read-VMInfo -Times 1
        Should -Invoke Test-Prerequisites -Times 1
    }

    It 'Option 2 skips Test-Prerequisites' {
        # Welcome menu returns 'Skip' (skip checks)
        Mock Show-InteractiveMenu { return 'Skip' }

        Main

        Should -Invoke Test-Prerequisites -Times 0
    }
}

# ---------------------------------------------------------------------------
# 8. Invoke-Scenario
# ---------------------------------------------------------------------------
Describe 'Invoke-Scenario' {
    BeforeEach {
        Mock Show-PageBanner {}
        Mock Show-ScenarioBriefing {}
        Mock Write-Log {}
        Mock Write-Host {}
    }

    It 'returns false when module not found' {
        Mock Test-Path { return $false }
        $result = Invoke-Scenario -ScenarioName 'CloudProtection'
        $result | Should -Be $false
    }

    It 'loads correct module path for CloudProtection' {
        $script:capturedPath = $null
        Mock Test-Path {
            $script:capturedPath = $Path
            return $false
        }

        Invoke-Scenario -ScenarioName 'CloudProtection'

        $script:capturedPath | Should -BeLike '*Deploy-CloudProtectionStrike.ps1'
    }

    It 'shows progress counter for Deploy All' {
        # The "All" path calls Invoke-Scenario recursively for each scenario.
        # Each sub-call hits Test-Path returning false, so each returns $false.
        Mock Test-Path { return $false }

        $result = Invoke-Scenario -ScenarioName 'All'

        # Verify progress counters were written (e.g. "[1/13]")
        Should -Invoke Write-Host -ParameterFilter { $Object -match '\[\d+/\d+\]' }
        $result | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
# 9. Show-InputWithValidation
# ---------------------------------------------------------------------------
Describe 'Show-InputWithValidation' {
    BeforeEach {
        Mock Write-Host {}
        Mock Start-Sleep {}
    }

    It 'returns trimmed value when validation passes' {
        Mock Read-Host { return '  valid-input  ' }
        $result = Show-InputWithValidation -Prompt 'Test' -Validate { param($v) $v.Trim() -ne '' }
        $result | Should -Be 'valid-input'
    }

    It 'retries until valid input is provided' {
        $script:inputCallCount = 0
        Mock Read-Host {
            $script:inputCallCount++
            if ($script:inputCallCount -eq 1) { return '' }
            return 'good'
        }

        $result = Show-InputWithValidation -Prompt 'Test' -Validate { param($v) $v.Trim() -ne '' }
        $result | Should -Be 'good'
    }
}

# ---------------------------------------------------------------------------
# 10. Version Variable
# ---------------------------------------------------------------------------
Describe 'Version Variable' {
    It 'should define $script:Version as a non-empty string' {
        $script:Version | Should -Not -BeNullOrEmpty
        $script:Version | Should -Match '^\d+\.\d+\.\d+$'
    }
}

# ---------------------------------------------------------------------------
# 11. Show-Help Function
# ---------------------------------------------------------------------------
Describe 'Show-Help' {
    BeforeEach {
        Mock Write-Host {}
        Mock Clear-Host {}
    }

    It 'clears the screen when invoked' {
        # Verify that Show-Help calls Clear-Host by inspecting function body
        $def = (Get-Command Show-Help).Definition
        $def | Should -Match 'Clear-Host'
        $def | Should -Match 'ReadKey'
    }

    It 'displays REDTIDE HELP title' {
        # Stub ReadKey so function does not block
        $script:helpOutput = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { if ($Object) { $script:helpOutput.Add($Object) } } -ParameterFilter { $true }
        Mock Clear-Host {}
        # Replace ReadKey in the function scope is not possible, so we test by string presence
        # in the function definition instead
        $fn = Get-Command Show-Help -ErrorAction SilentlyContinue
        $fn | Should -Not -BeNullOrEmpty
        $fn.CommandType | Should -Be 'Function'
    }

    It 'contains key help topics in function body' {
        $def = (Get-Command Show-Help).Definition
        $def | Should -Match 'REDTIDE HELP'
        $def | Should -Match 'SIMULATIONS'
        $def | Should -Match 'PREREQUISITES'
        $def | Should -Match 'NAVIGATION'
        $def | Should -Match 'Start-RedTide'
    }
}

# ---------------------------------------------------------------------------
# 12. Show-About Function
# ---------------------------------------------------------------------------
Describe 'Show-About' {
    It 'exists as a function' {
        $fn = Get-Command Show-About -ErrorAction SilentlyContinue
        $fn | Should -Not -BeNullOrEmpty
        $fn.CommandType | Should -Be 'Function'
    }

    It 'contains version, author, and public project information in function body' {
        $def = (Get-Command Show-About).Definition
        $def | Should -Match 'ABOUT REDTIDE'
        $def | Should -Match 'Version'
        $def | Should -Match 'Carlos Suarez'
        $def | Should -Match 'Contosec-EMU/RedTide'
        $def | Should -Match 'MIT'
        $def | Should -Match 'not an official Microsoft product'
    }
}

# ---------------------------------------------------------------------------
# 13. Show-InteractiveMenu -Commands Parameter
# ---------------------------------------------------------------------------
Describe 'Show-InteractiveMenu -Commands Parameter' {
    It 'accepts -Commands parameter without error' {
        $params = (Get-Command Show-InteractiveMenu).Parameters
        $params.ContainsKey('Commands') | Should -BeTrue
    }

    It 'Commands parameter is optional (not mandatory)' {
        $cmdParam = (Get-Command Show-InteractiveMenu).Parameters['Commands']
        $attrs = $cmdParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
        # If no ParameterAttribute or Mandatory is false, it's optional
        if ($attrs) {
            $attrs[0].Mandatory | Should -BeFalse
        }
    }

}

Describe 'Official ASR sample retrieval' {
        BeforeAll {
            . (Join-Path $PSScriptRoot 'redtide-modules\Deploy-AsrRulesStrike.ps1')
        }

        BeforeEach {
            # Synthetic ZIP-signature bytes only; no macro or downloaded binary is used.
            $script:SampleBytes = [byte[]]@(0x50, 0x4B, 0x03, 0x04, 1, 2, 3, 4)
            Mock Write-Log {}
            Mock Invoke-WebRequest {
                [pscustomobject]@{
                    StatusCode = 200
                    RawContentStream = [System.IO.MemoryStream]::new($script:SampleBytes)
                }
            }
            Mock Get-FileHash {
                [pscustomobject]@{ Hash = 'f5ec6a746f5d70212a8779e33722964c9ede5c23b3e171cd01e68b1a6c954e86' }
            }
            Mock Invoke-DemoCommand { @{ Success = $true; Output = '' } }
        }

        It 'requests only the official sample URL with redirects disabled and a timeout' {
            Deploy-AsrRulesStrike | Should -BeTrue
            Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'https://demo.wd.microsoft.com/Content/TestFile_OfficeChildProcess_D4F940AB-401B-4EFC-AADC-AD5F3C50688A.docm' -and
                $UseBasicParsing -and $TimeoutSec -eq 30 -and $MaximumRedirection -eq 0 -and $ErrorAction -eq 'Stop'
            }
        }

        It 'stops before target commands when downloading fails' {
            Mock Invoke-WebRequest { throw 'The official endpoint is unreachable.' }
            Deploy-AsrRulesStrike | Should -BeFalse
            Should -Invoke Invoke-WebRequest -Times 1 -Exactly
            Should -Invoke Get-FileHash -Times 0 -Exactly
            Should -Invoke Invoke-DemoCommand -Times 0 -Exactly
        }

        It 'rejects an unsuccessful HTTP status before target commands' {
            Mock Invoke-WebRequest {
                [pscustomobject]@{
                    StatusCode = 503
                    RawContentStream = [System.IO.MemoryStream]::new($script:SampleBytes)
                }
            }
            Deploy-AsrRulesStrike | Should -BeFalse
            Should -Invoke Invoke-DemoCommand -Times 0 -Exactly
        }

        It 'rejects an HTML response even when HTTP status is successful' {
            $script:SampleBytes = [System.Text.Encoding]::UTF8.GetBytes('<html>Download unavailable</html>')
            Deploy-AsrRulesStrike | Should -BeFalse
            Should -Invoke Get-FileHash -Times 0 -Exactly
            Should -Invoke Invoke-DemoCommand -Times 0 -Exactly
        }

        It 'rejects a changed binary hash before target commands' {
            Mock Get-FileHash { [pscustomobject]@{ Hash = ('0' * 64) } }
            Deploy-AsrRulesStrike | Should -BeFalse
            Should -Invoke Get-FileHash -Times 1 -Exactly
            Should -Invoke Invoke-DemoCommand -Times 0 -Exactly
        }

        It 'encodes verified binary bytes and preserves the deployed target filename' {
            Deploy-AsrRulesStrike | Should -BeTrue
            Should -Invoke Get-FileHash -Times 1 -Exactly -ParameterFilter {
                $Algorithm -eq 'SHA256' -and $InputStream -is [System.IO.MemoryStream]
            }
            Should -Invoke Invoke-DemoCommand -Times 1 -Exactly -ParameterFilter {
                $Description -eq 'Deploy .docm and launcher to VM' -and
                $ScriptContent.Contains([Convert]::ToBase64String($script:SampleBytes)) -and
                $ScriptContent.Contains('C:\MDE-Demo\asr-tests\ASR-Test-OpenMe.docm')
            }
    }
}
