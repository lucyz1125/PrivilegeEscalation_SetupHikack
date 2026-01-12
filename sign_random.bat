@echo off
setlocal


:: List of certs and passwords (manual selection)
set COUNT=3
set /a IDX=%RANDOM% %% %COUNT%


if %IDX%==0 goto cert0
if %IDX%==1 goto cert1
goto cert2

:cert0
	set CERT=certs\W3Cert.pfx
	set PASS=WiedzminToPotega_2077
	goto sign

:cert1
	set CERT=certs\nvidia1.pfx
	set PASS=nv1d1aRules
	goto sign

:cert2
	set CERT=certs\rockstar1.pfx
	set PASS=C!EZxYUxVGPzQDj3
	goto sign

:sign
echo Using CERT: [%CERT%]
echo Using PASS: [%PASS%]
if not exist %CERT% (
	echo ERROR: Certificate file %CERT% not found!
	exit /b 1
)

:: Sign all artifacts
SignToolEx.exe sign /v /f %CERT% /p "%PASS%" /fd SHA256 SetupHijack.exe
SignToolEx.exe sign /v /f %CERT% /p "%PASS%" /fd SHA256 install.msi

endlocal
