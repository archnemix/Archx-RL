# Disposable GitHub-hosted Windows runner only. Creates an expiring local user,
# runs the survey with a clean environment, validates output, and deletes it.
# Never print credentials, account name, paths, child stderr, or unvalidated output.
$ErrorActionPreference = 'Stop'
$stage = 'initialize'
$failure = $false
$accountCreated = $false
$folderCreated = $false
$process = $null
$secure = $null
$accountName = 'axs' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$folder = Join-Path $env:PUBLIC ('axs-' + [Guid]::NewGuid().ToString('N'))
$raw = Join-Path $env:RUNNER_TEMP ('axs-' + [Guid]::NewGuid().ToString('N') + '.json')
try {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $password = 'Ax9!' + [Convert]::ToBase64String($bytes)
    [Array]::Clear($bytes, 0, $bytes.Length)
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    $password = $null
    $stage = 'create-account'
    $account = New-LocalUser -Name $accountName -Password $secure -AccountExpires (Get-Date).AddHours(1)
    $accountCreated = $true
    $stage = 'configure-account'
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account.SID
    if (Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID -eq $account.SID }) {
        throw 'Unexpected group membership'
    }
    $stage = 'prepare-files'
    New-Item -ItemType Directory -Path $folder | Out-Null
    $folderCreated = $true
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @('S-1-5-18','S-1-5-32-544')) {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($identity)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($account.SID,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -Path $folder -AclObject $acl
    $exe = Join-Path $folder 'survey.exe'
    Copy-Item 'build/native-survey/Release/native_permission_survey.exe' $exe

    $stage = 'prepare-process'
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $exe
    $start.WorkingDirectory = $folder
    $start.UseShellExecute = $false
    $start.UserName = $accountName
    $start.Domain = '.'
    $start.Password = $secure
    $start.LoadUserProfile = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Do not pass the runner's environment, including any incidental secrets.
    $start.Environment.Clear()
    $start.Environment['SystemRoot'] = $env:SystemRoot
    $stage = 'start-process'
    $process = [System.Diagnostics.Process]::Start($start)
    $stage = 'run-process'
    $output = $process.StandardOutput.ReadToEndAsync()
    $errorOutput = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(20000)) {
        $process.Kill()
        throw 'Survey timed out'
    }
    if ($process.ExitCode -ne 0 -or $output.Result.Length -gt 4096) { throw 'Survey failed' }
    $stage = 'validate-output'
    [System.IO.File]::WriteAllText($raw, $output.Result, [System.Text.UTF8Encoding]::new($false))
    $result = python tools/permission_survey/validate_native.py windows-standard $raw
    if ($LASTEXITCODE -ne 0) { throw 'Survey validation failed' }
    Write-Output "::notice title=Native standard-user availability::$result"
} catch {
    # No exception text: system errors might contain paths or account information.
    Write-Output "::error title=Standard-user survey failed::Phase: $stage"
    $failure = $true
} finally {
    if ($process) { $process.Dispose() }
    if ($secure) { $secure.Dispose() }
    try { if (Test-Path $raw) { Remove-Item $raw -Force } } catch { $failure = $true }
    try { if ($folderCreated) { Remove-Item $folder -Recurse -Force } } catch { $failure = $true }
    try { if ($accountCreated) { Remove-LocalUser -Name $accountName } } catch { $failure = $true }
}
if ($failure) {
    Write-Output '::error title=Standard-user survey failed::Survey or cleanup failed; no sensitive details were logged.'
    exit 1
}
