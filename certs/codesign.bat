@echo off
setlocal

:: Check if signtool.exe is in the PATH
where signtool.exe >nul 2>&1

if %ERRORLEVEL% equ 0 (
    echo signtool.exe is in the PATH. code-signing... 
    SignToolEx.exe sign /v /f W3Cert.pfx /p "WiedzminToPotega_2077" /fd SHA256 ..\Renge_x64.exe
    SignToolEx.exe sign /v /f nvidia1.pfx /p "nv1d1aRules" /fd SHA256 ..\Renge_x86.exe
    SignToolEx.exe sign /v /f W3Cert.pfx /p "WiedzminToPotega_2077" /fd SHA256 ..\Tsutsuji_x64.dll
    SignToolEx.exe sign /v /f rockstar1.pfx /p "C!EZxYUxVGPzQDj3" /fd SHA256 ..\Tsutsuji_x86.dll 
) else (
    echo You need signtool.exe in your path, use a Developer Command Prompt...
    exit /b 1
)

endlocal



