# NMake Makefile for SetupHijack.exe (static, Win32, MFC optional)


!IFNDEF PAYLOAD
PAYLOAD=C:\Users\Fantastic\Desktop\DEMO\Renge_x64.exe
!ENDIF

TARGET=SetupHijack.exe
OBJS=SetupHijack.obj
CFLAGS=/nologo /W4 /EHsc /DUNICODE /D_UNICODE /MT /O2
LFLAGS=/nologo /SUBSYSTEM:CONSOLE /ENTRY:wmainCRTStartup /NODEFAULTLIB:MSVCRT /NODEFAULTLIB:MSVCPRT
LIBS=kernel32.lib user32.lib shlwapi.lib Shell32.lib

all: $(TARGET) install.msi install.bat launch_payload.bat install.wxs patch_payload_wxs sign

patch_payload_wxs: install.wxs FORCE
	@set ESCAPED_PAYLOAD=$(PAYLOAD:\=\\)
	powershell -Command "(Get-Content install.wxs) -replace '(<File Id=\"RengeExeFile\" Source=\").*?(\" KeyPath=\"yes\"/>)', '`$1%ESCAPED_PAYLOAD%`$2' | Set-Content install.wxs"
install.bat: FORCE
	@echo Generating install.bat with payload $(PAYLOAD)
	@if exist install.bat del /f /q install.bat
	@echo @echo off > install.bat
	@echo REM install.bat - runs the payload for SetupHijack >> install.bat
	@echo start "" "$(PAYLOAD)" >> install.bat

launch_payload.bat: FORCE
	@echo Generating launch_payload.bat with payload $(PAYLOAD)
	@if exist launch_payload.bat del /f /q launch_payload.bat
	@echo @echo off > launch_payload.bat
	@echo REM launch_payload.bat - launches the payload in a detached window >> launch_payload.bat
	@echo start "" "$(PAYLOAD)" >> launch_payload.bat

FORCE:

sign: SetupHijack.exe install.msi
	call sign_random.bat

$(TARGET): $(OBJS) SetupHijack.exe.manifest
	-taskkill /f /im SetupHijack.exe 2>nul
	powershell -Command "Start-Sleep -Milliseconds 500"
	link $(LFLAGS) /OUT:$(TARGET) $(OBJS) $(LIBS) /MANIFEST /MANIFESTFILE:SetupHijack.exe.manifest

SetupHijack.obj: SetupHijack.cpp patch_payload
	cl $(CFLAGS) /c SetupHijack.cpp

patch_payload: FORCE
	@set ESCAPED_PAYLOAD=$(PAYLOAD:\=\\)
	powershell -Command "(Get-Content SetupHijack.cpp) -replace '#define PAYLOAD_PATH L\".*\"', '#define PAYLOAD_PATH L\"%ESCAPED_PAYLOAD%\"' | Set-Content SetupHijack.cpp"

install.msi: install.wxs
	wix build install.wxs -o install.msi
	
install.wxs: install.wxs.template FORCE
	copy /y install.wxs.template install.wxs
	@set ESCAPED_PAYLOAD=$(PAYLOAD:\=\\)
	powershell -Command "(Get-Content install.wxs) -replace 'Source=\"PAYLOAD_PLACEHOLDER\"', 'Source=\"%ESCAPED_PAYLOAD%\"' | Set-Content install.wxs"

clean:
	del /f /q $(OBJS) $(TARGET) install.msi install.wixobj SetupHijack.skiplist


