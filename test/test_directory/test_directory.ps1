# This test will attempt to encrypt and decrypt files to a directory or
# directories themselves.  All tests should fail with specific errors,
# as sources and destinations must be files, not directories.

param (
    [string]$AESCRYPT
)

if (-not (Test-Path "$AESCRYPT")) {
    Write-Output "AES Crypt executable not found: $AESCRYPT"
    exit 1
}

# Attempt to encrypt a directory (this should fail)
$result =
    & {
        try
        {
            & "$AESCRYPT" -q -e -p secret -o - "$env:WINDIR" 2>&1
        }
        catch
        {
            Write-Output $_
            exit 1
        }
    }

if ($LASTEXITCODE -eq 0)
{
    Write-Output "Attempt to encrypt a directory should have failed"
    exit 1
}

if ($result.Trim() -ne "Input name is not a file: $env:WINDIR")
{
    Write-Output "Unexpected output: $result"
    exit 1
}

# Attempt to encrypt a file writing into a directory (this should fail)
$result =
    & {
        try
        {
            & "$AESCRYPT" -q -e -p secret -o "$env:WINDIR" "$env:WINDIR\win.ini" 2>&1
        }
        catch
        {
            Write-Output $_
            exit 1
        }
    }

if ($LASTEXITCODE -eq 0)
{
    Write-Output "Attempt to encrypt to a directory should have failed"
    exit 1
}

if ($result.Trim() -ne "Target output cannot be a directory: $env:WINDIR")
{
    Write-Output "Unexpected output: $result"
    exit 1
}

# Attempt to decrypt a directory (this should fail)
$result =
    & {
        try
        {
            & "$AESCRYPT" -q -d -p secret -o - "$env:WINDIR" 2>&1
        }
        catch
        {
            Write-Output $_
            exit 1
        }
    }

if ($LASTEXITCODE -eq 0)
{
    Write-Output "Attempt to decrypt a directory should have failed"
    exit 1
}

if ($result.Trim() -ne "Input name is not a file: $env:WINDIR")
{
    Write-Output "Unexpected output: $result"
    exit 1
}

# Attempt to decrypt a file writing into a directory (this should fail)
$result =
    & {
        try
        {
            & "$AESCRYPT" -q -d -p secret -o "$env:WINDIR" "$env:WINDIR\win.ini" 2>&1
        }
        catch
        {
            Write-Output $_
            exit 1
        }
    }

if ($LASTEXITCODE -eq 0)
{
    Write-Output "Attempt to decrypt to a directory should have failed"
    exit 1
}

if ($result.Trim() -ne "Target output cannot be a directory: $env:WINDIR")
{
    Write-Output "Unexpected output: $result"
    exit 1
}

exit 0
