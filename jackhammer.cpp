// Jackhammer by Dr_J0nes

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include <nlohmann/json.hpp>
#include <wincrypt.h>


#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#ifdef _DEBUG
    #define DEBUG_LOGS
#endif


class Logger {
public:
    Logger(std::ostream& os = std::cout) : out(os) {}

    template<typename T>
    Logger& operator<<(const T& val) {
        out << val;
        return *this;
    }

    Logger& operator<<(std::ostream& (*manip)(std::ostream&)) {
        out << manip;
        return *this;
    }

private:
    std::ostream& out;
};

#ifdef DEBUG_LOGS
using DebugLogger = Logger;
#else

class DebugLogger {
public:
    template<typename T>
    DebugLogger& operator<<(const T&) { return *this; }

    DebugLogger& operator<<(std::ostream& (*)(std::ostream&)) { return *this; }
};

#endif

Logger Log;
DebugLogger DebugLog;

using json = nlohmann::json;

struct PatchEntry {
    std::vector<BYTE> bytes;
    int numInstructions = 0;
    std::vector<BYTE> originalBytes;
    std::vector<BYTE> checkBytes;
    bool isSet = false;
};

std::string ToLowerHex(uint8_t byte) {
    std::ostringstream oss;
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return oss.str();
}

std::string ComputeSHA256(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Failed opening file.");

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[32];
    DWORD cbHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        throw std::runtime_error("CryptAcquireContext failed");

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        throw std::runtime_error("CryptCreateHash failed");

    std::vector<char> buffer(8192);
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        if (!CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer.data()), file.gcount(), 0))
            throw std::runtime_error("CryptHashData failed");
    }

    cbHash = sizeof(rgbHash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
        throw std::runtime_error("CryptGetHashParam failed");

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::ostringstream oss;
    for (DWORD i = 0; i < cbHash; ++i) oss << ToLowerHex(rgbHash[i]);
    return oss.str();
}

std::vector<BYTE> ParseHexBytes(const std::string& line) {
    std::istringstream iss(line);
    std::vector<BYTE> bytes;
    std::string byteStr;
    while (iss >> byteStr) {
        if (byteStr[0] == '/' || byteStr[0] == '"') break;
        bytes.push_back(static_cast<BYTE>(std::stoul(byteStr, nullptr, 16)));
    }
    return bytes;
}

DWORD64 GetImageBase(DWORD pid, const std::wstring& exeName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W modEntry = { 0 };
    modEntry.dwSize = sizeof(modEntry);

    if (Module32FirstW(hSnapshot, &modEntry)) {
        do {
            if (exeName == modEntry.szModule) {
                CloseHandle(hSnapshot);
                return reinterpret_cast<DWORD64>(modEntry.modBaseAddr);
            }
        } while (Module32NextW(hSnapshot, &modEntry));
    }

    CloseHandle(hSnapshot);
    return 0;
}

std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);

	// remove the null character
    wstr.pop_back();
    return wstr;
}


std::string getFileNameFromPath(const std::string& fullPath) {
    size_t pos = fullPath.find_last_of("\\/");
    if (pos == std::string::npos)
        return fullPath;
    return fullPath.substr(pos + 1);
}

#include <psapi.h>

// explicit "not-found"-Value:
static inline DWORD64 kNotFound() { return (DWORD64) -1; }

static DWORD64 FindInBuffer(const BYTE* hay, SIZE_T haySize, const std::vector<BYTE>& needle) {
    if (needle.empty() || haySize < needle.size()) return kNotFound();
    for (SIZE_T i = 0; i + needle.size() <= haySize; ++i) {
        if (memcmp(hay + i, needle.data(), needle.size()) == 0)
            return (DWORD64)i; // 0 is an invalid match!
    }
    return kNotFound();
}

// searches only in Main Module (imageBase .. imageBase + SizeOfImage), returns absolute VA.
static DWORD64 FindPayloadInMainModule(HANDLE hProcess, DWORD64 imageBase, const std::vector<BYTE>& payload) {
    if (imageBase == 0 || payload.empty()) return 0;

    MODULEINFO mi{};
    if (!GetModuleInformation(hProcess, (HMODULE)imageBase, &mi, sizeof(mi))) {
        return 0;
    }

    const DWORD64 modStart = (DWORD64)imageBase;
    const SIZE_T  modSize = (SIZE_T)mi.SizeOfImage;

    // read in Chunks (e.g. 64KB) with Overlap (needle.size()-1)
    const SIZE_T CHUNK = 64 * 1024;
    const SIZE_T overlap = payload.size() > 0 ? payload.size() - 1 : 0;

    std::vector<BYTE> buf;
    buf.reserve(CHUNK + overlap);

    DWORD64 cursor = modStart;
    DWORD64 modEnd = modStart + modSize;

    while (cursor < modEnd) {
        SIZE_T toRead = (SIZE_T)std::min<DWORD64>(CHUNK, modEnd - cursor);
        buf.resize(toRead + (cursor == modStart ? 0 : overlap));

        SIZE_T read = 0;
		// From Chunk two we keep the front Overlap from the previous Read:
        BYTE* dst = buf.data();
        if (cursor != modStart) {
			// move last 'overlap' Bytes from previous Buffer to the Start
			// (here more easy: we store it in Buffer, only move the Target for Read)
            dst += overlap;
        }

        if (!ReadProcessMemory(hProcess, (LPCVOID)cursor, dst, toRead, &read) || read == 0) {
			// if reading fails, abort
            return 0;
        }

        SIZE_T haySize = (cursor == modStart) ? read : (read + overlap);
        DWORD64 off = FindInBuffer(buf.data(), haySize, payload);
        if (off != kNotFound()) {
            // return absolute VA
            return (cursor - (cursor == modStart ? 0 : overlap)) + off;
        }

        if (read < toRead) {
            // EOF inside Module (should not happen, but for safety)
            break;
        }
        cursor += toRead - overlap;
    }

    return 0;
}


int main(int argc, char* argv[]) {
    Log << "Jackhammer started!\nmade by Dr_J0nes\n\n";

#ifndef _DEBUG
    if (argc < 2) {
        std::cerr << "No filepath set! Start this application via command and append the path to the target application.\n";
        return 1;
    }

    DebugLog << "Target Application Path: " << argv[1] << std::endl;
#endif

    std::ifstream cfgFile("config.json");
    if (!cfgFile) {
        std::cerr << "Unable to load config.json.\n";
        return 1;
    }

    json cfg;
    cfgFile >> cfg;

    std::string appPath = argv[1];
    std::string appFileName = getFileNameFromPath(appPath);


    // list Processes and attach to Target Process
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Toolhelp Snapshot failed\n";
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!Process32First(hSnap, &pe)) {
        std::cerr << "Process32First failed\n";
        CloseHandle(hSnap);
        return 1;
    }

    do {
        //if (_wcsicmp(pe.szExeFile, std::wstring(appPath.begin(), appPath.end()).c_str()) == 0 || std::wstring(pe.szExeFile).find(utf8_to_wstring(appFileName)) != std::wstring::npos) { // to lower?
		if (_stricmp(pe.szExeFile, appFileName.c_str()) == 0 || std::string(pe.szExeFile).find(appFileName) != std::string::npos) { // to lower?
            pid = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnap, &pe));

    CloseHandle(hSnap);

    if (!pid) {
        std::cerr << "Target process not found. Make sure the process is running.\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed.\n";
        return 1;
    }

    if (!DebugActiveProcess(pid)) {
        std::cerr << "DebugActiveProcess failed. Error: " << GetLastError() << "\n";
        return 1;
    }

    DWORD64 imageBase = GetImageBase(pid, utf8_to_wstring(appFileName)); // to lower?
    if (imageBase == 0) {
        std::wcerr << L"Error: Unable to determine image base of target process.\n";
        return 1;
    }
    DebugLog << "imageBase: " << imageBase << "\n";

    std::string payloadHex = cfg["payload"];
    std::vector<BYTE> payload = ParseHexBytes(payloadHex);
    if (payload.empty()) {
        std::wcerr << L"Error: Payload in config is empty or invalid.\n";
        return 1;
    }

    SIZE_T imageSize = 0;
    DWORD64 payloadAddr = 0;
    DebugLog << "Searching for payload..\n";
    payloadAddr = FindPayloadInMainModule(hProcess, imageBase, payload);
 
    if (payloadAddr == 0) {
        std::wcerr << L"Error: Payload bytes not found in target process.\n";
        return 1;
    }

    DebugLog << "Payload found at 0x" << std::hex << payloadAddr << std::dec << "\n";


    std::map<DWORD64, PatchEntry> breakpoints;
    for (auto it = cfg["patches"].begin(); it != cfg["patches"].end(); ++it) {
        DWORD64 offset = std::stoull(it.key(), nullptr, 0);
        DWORD64 addr = payloadAddr + offset;
        PatchEntry entry;

        DebugLog << "Creating breakpoint 0x" << std::hex << offset << " at 0x" << addr << std::dec << "\n";

        if (it.value().is_array()) {
            bool isFirstEntry = true;
            for (const auto& line : it.value()) {
                if (isFirstEntry) {
                    DebugLog << "DEBUG reading patch instruction\n";

                    auto parsed = ParseHexBytes(line);
                    entry.bytes.insert(entry.bytes.end(), parsed.begin(), parsed.end());
                    entry.numInstructions = 1;

                    isFirstEntry = false;
                }
                else {
                    DebugLog << "DEBUG reading check bytes\n";

                    auto parsed = ParseHexBytes(line);
                    entry.checkBytes.insert(entry.checkBytes.end(), parsed.begin(), parsed.end());
                }
            }
        }
        else {
            std::cerr << "Check bytes missing!\n";
        }

        DebugLog << "DEBUG check original bytes\n";

        // read Original Bytes from process and compare with Check Bytes
        std::vector<BYTE> originals(entry.bytes.size());
        SIZE_T read;
        if (ReadProcessMemory(hProcess, (LPCVOID)addr, originals.data(), entry.bytes.size(), &read) && read == entry.bytes.size()) {
            DebugLog << "DEBUG reading process memory\n";
            entry.originalBytes = originals;

            for (size_t i = 0; i < entry.checkBytes.size(); ++i) {
                DebugLog << std::hex << (int)entry.checkBytes[i] << " ; " << (int)entry.originalBytes[i] << std::dec << "\n";

                if (entry.checkBytes[i] != entry.originalBytes[i]) {
                    std::wcerr << L"Check bytes dont match at offset " << i << L".\n";
                    return 1;
                }
            }

            // set Breakpoint
            BYTE int3 = 0xCC;
            SIZE_T written;
            if (WriteProcessMemory(hProcess, (LPVOID)(addr - 0), &int3, 1, &written) && written == 1) {
                FlushInstructionCache(hProcess, (LPCVOID)(addr - 0), 1);
                entry.isSet = true;
                DebugLog << "Set breakpoint at 0x" << std::hex << addr << ".\n" << std::dec;
            }
            else {
                std::cerr << "Failed to set a breakpoint.\n";
                return 1;
            }
        }

        DebugLog << "\n";

        breakpoints[addr] = entry;
    }

    DebugLog << "Finished. Waiting for breakpoints\n\n";

    
    DWORD64 currentInjectionBaseAddress = 0;
    DWORD64 currentInjectionOriginalPostInstructionAddress = 0;
    int numPatchinstrcutionsExecuted = 0;

    DEBUG_EVENT dbgEvent;
    while (true) {
        if (!WaitForDebugEvent(&dbgEvent, INFINITE)) {
            std::cerr << "WaitForDebugEvent failed\n";
            break;
        }

        ///std::cout << "DEBUG debug event triggered\n";

        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            ///std::cout << "DEBUG exception event triggered\n";

            auto& info = dbgEvent.u.Exception;
            DWORD exceptionCode = info.ExceptionRecord.ExceptionCode;

            DWORD64 exceptionAddr = reinterpret_cast<DWORD64>(info.ExceptionRecord.ExceptionAddress);
            ///std::cout << "DEBUG exception Address: 0x" << std::hex << exceptionAddr << std::dec << "\n";

            if (exceptionAddr == 0) {
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                continue;
            }

            if ((exceptionCode != EXCEPTION_BREAKPOINT) && (exceptionCode != EXCEPTION_SINGLE_STEP)) {
                auto& rec = dbgEvent.u.Exception.ExceptionRecord;

                DebugLog << "DEBUG Exception code: " << std::hex << rec.ExceptionCode << "\n";
                DebugLog << "DEBUG Exception addr: " << rec.ExceptionAddress << std::dec << "\n";

                if (rec.NumberParameters >= 2) {
                    DebugLog << "  DEBUG Access type: " << rec.ExceptionInformation[0] << "\n";
                    DebugLog << "  DEBUG Access addr: " << std::hex << rec.ExceptionInformation[1] << std::dec << "\n";
                }

                if (numPatchinstrcutionsExecuted > 0)
                    return 1;

                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                continue;
            }

            DWORD64 ta = exceptionAddr;
            if (currentInjectionBaseAddress != 0)
                ta = currentInjectionBaseAddress;

            auto it = breakpoints.find(ta);
            if (it == breakpoints.end()) {
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                continue;
            }
            PatchEntry& patch = it->second;

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
            if (!hThread) {
                DebugLog << "DEBUG thread opening error!\n";
                break;
            }
            DebugLog << "DEBUG opened thread successfully\n";

            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;

            if (!GetThreadContext(hThread, &ctx)) {
                DebugLog << "DEBUG get thread context error!\n";
                break;
            }
            DebugLog << "DEBUG got thread context\n";

            if (exceptionCode == EXCEPTION_BREAKPOINT) {
				// todo: make optionally silent
                Log << "B";
                unsigned int brAmount = static_cast<unsigned int>(patch.originalBytes[0] % (12 + 1)) + 1;
                unsigned int exAmount = static_cast<unsigned int>(exceptionAddr % (5 + 1)) + 1;
                for (unsigned int i = 0; i < brAmount; i++)
                    Log << "r";
                for (unsigned int i = 0; i < exAmount; i++)
                    Log << "!";
                Log << "\n";

                DebugLog << "at: 0x" << std::hex << exceptionAddr << std::dec << "\n";

                ctx.EFlags |= 0x100; // set Trap Flag for Single-Step
                if (!SetThreadContext(hThread, &ctx)) {
                    DebugLog << "DEBUG error setting thread context!\n";
                    break;
                }
                DebugLog << "DEBUG set thread context successfull\n";

                // restore Original Byte
                WriteProcessMemory(hProcess, (LPVOID)exceptionAddr, &patch.originalBytes[0], 1, nullptr);
                FlushInstructionCache(hProcess, (LPCVOID)exceptionAddr, 1);

                // reset RIP, so INT3 repeats
                ctx.Rip = exceptionAddr;
                SetThreadContext(hThread, &ctx);

                currentInjectionBaseAddress = exceptionAddr;
            }
            else if (exceptionCode == EXCEPTION_SINGLE_STEP) {
                DebugLog << "DEBUG exception single-step triggered\n";

                if (currentInjectionBaseAddress != 0) {
                    if (numPatchinstrcutionsExecuted < patch.numInstructions) {
                        if (currentInjectionOriginalPostInstructionAddress == 0) {
                            currentInjectionOriginalPostInstructionAddress = ctx.Rip;

                            WriteProcessMemory(hProcess, (LPVOID)currentInjectionBaseAddress, patch.bytes.data(), patch.bytes.size(), nullptr);
                            FlushInstructionCache(hProcess, (LPCVOID)currentInjectionBaseAddress, patch.bytes.size());

                            ctx.Rip = currentInjectionBaseAddress;
                            SetThreadContext(hThread, &ctx);

                            DebugLog << "DEBUG patched bytes\n";
                        }

                        ctx.EFlags |= 0x100; // set Trap Flag for Single-Step
                        if (!SetThreadContext(hThread, &ctx)) {
                            DebugLog << "DEBUG error setting thread context!\n";
                            break;
                        }
                        DebugLog << "DEBUG set thread context successfull\n";

                        SetThreadContext(hThread, &ctx);

                        numPatchinstrcutionsExecuted++;
                        DebugLog << "DEBUG executing step\n";
                    }
                    else {
                        // restore Original Bytes
                        WriteProcessMemory(hProcess, (LPVOID)currentInjectionBaseAddress, patch.originalBytes.data(), patch.originalBytes.size(), nullptr);
                        FlushInstructionCache(hProcess, (LPCVOID)currentInjectionBaseAddress, patch.originalBytes.size());

                        // restore ALL Breakpoints
                        BYTE int3 = 0xCC;
                        for (const auto& pel : breakpoints) {
                            WriteProcessMemory(hProcess, (LPVOID)pel.first, &int3, 1, nullptr);
                            FlushInstructionCache(hProcess, (LPCVOID)pel.first, 1);
                        }

                        ctx.Rip = currentInjectionOriginalPostInstructionAddress;
                        SetThreadContext(hThread, &ctx);

                        currentInjectionBaseAddress = 0;
                        currentInjectionOriginalPostInstructionAddress = 0;
                        numPatchinstrcutionsExecuted = 0;

                        ctx.EFlags &= ~0x100; // Trap Flag reset
                        if (!SetThreadContext(hThread, &ctx)) {
                            DebugLog << "DEBUG error setting thread context!\n";
                            break;
                        }

                        DebugLog << "DEBUG finished patching\n";
                    }                    
                }
            }

            if (hThread)
                CloseHandle(hThread);
        }

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    }

    CloseHandle(hProcess);
    return 0;
}
