#define _CRT_SECURE_NO_WARNINGS
#include "injector.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include <stdlib.h>
#include "injector.h"

#define PIPE_NAME L"\\\\.\\pipe\\MyNamedPipe"

Injector::Injector() : hPipe(INVALID_HANDLE_VALUE), funcName(""), mode(""), processId(-1), procName(new char[100]) {
    ;
}
Injector::~Injector() {
    delete(procName);
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);
}

void Injector::setProcName(const char* name) {
    this->procName = name;
}
void Injector::setFuncName(std::string func) {
    this->funcName = func;
}
void Injector::setMode(std::string mode) {
    this->mode = mode;
}
void Injector::setProcessID(DWORD id) {
    this->processId = id;
}

void Injector::setFileName(std::string name) {
    this->fileName = name;
}

const char* Injector::getProcName() {
    return this->procName;
}

std::string Injector::getFuncName() {
    return this->funcName;
}
std::string Injector::getMode() {
    return this->mode;
}
DWORD Injector::getProcessID() {
    return this->processId;
}

std::string Injector::getFileName() {
    return this->fileName;
}


void Injector::inject() {
    std::cout << "injecting!" << std::endl;
    HANDLE openedProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (openedProcess == NULL)
    {
        std::cerr << "OpenProcess error code: " << GetLastError() << std::endl;
        return;
    }
    HMODULE kernelModule = GetModuleHandleW(L"kernel32.dll");
    if (!kernelModule) {
        std::cerr << "Can't find kernel module!" << std::endl;
        return;
    }

    FARPROC targetFunction = GetProcAddress(kernelModule, "LoadLibraryA");
    if (!targetFunction) {
        std::cerr << "Can't find function address!" << std::endl;
        return;
    }
    LPVOID argLoadLibrary = (LPVOID)VirtualAllocEx(openedProcess, NULL, strlen(dllName) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (argLoadLibrary == NULL)
    {
        std::cerr << "VirtualAllocEx error code: " << GetLastError() << std::endl;
        return;
    }
    int countWrited = WriteProcessMemory(openedProcess, argLoadLibrary, (LPCVOID)dllName, strlen(dllName) + 1, 0);
    if (countWrited == NULL)
    {
        std::cerr << "WriteProcessMemory error code: " << GetLastError() << std::endl;
        return;
    }
    HANDLE threadID = CreateRemoteThread(openedProcess, NULL, 0, (LPTHREAD_START_ROUTINE)targetFunction, argLoadLibrary, NULL, NULL);

    if (threadID == NULL)
    {
        std::cerr << "CreateRemoteThread error code: " << GetLastError() << std::endl;
        return;
    }
    else
        std::cout << "Dll injected!" << std::endl;
    CloseHandle(openedProcess);
}


void Injector::createPipe() {
    this->hPipe = CreateNamedPipe(
        PIPE_NAME,              // Pipe name
        PIPE_ACCESS_DUPLEX,     // Read/Write access
        PIPE_TYPE_MESSAGE |     // Message type pipe
        PIPE_READMODE_MESSAGE | // Message-read mode
        PIPE_WAIT,              // Blocking mode
        PIPE_UNLIMITED_INSTANCES, // Max. instances
        512,                    // Output buffer size
        512,                    // Input buffer size
        0,                      // Client time-out
        NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateNamedPipe failed: " << GetLastError() << std::endl;
        return;
    }

}

void Injector::connectPipe() {
    BOOL isConnected = ConnectNamedPipe(this->hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!isConnected) {
        std::cerr << "ConnectNamedPipe failed, GLE=" << GetLastError() << std::endl;
        CloseHandle(hPipe);
        return;
    }
}

bool Injector::readFromPipe(std::string& message) {
    if (hPipe == INVALID_HANDLE_VALUE) return false;

    char buffer[512];
    DWORD bytesRead;
    BOOL success = ReadFile(
        hPipe,
        buffer,
        sizeof(buffer) - 1,
        &bytesRead,
        NULL);

    if (!success || bytesRead == 0) {
        std::cerr << "ReadFile failed: " << GetLastError() << std::endl;
        return false;
    }

    buffer[bytesRead] = '\0';
    message = buffer;
    return true;
}

bool Injector::writeToPipe(const std::string& message) {
    if (hPipe == INVALID_HANDLE_VALUE) return false;

    DWORD bytesWritten;
    BOOL success = WriteFile(
        hPipe,
        message.c_str(),
        static_cast<DWORD>(message.size()),
        &bytesWritten,
        NULL);

    if (!success || bytesWritten != message.size()) {
        std::cerr << "WriteFile failed: " << GetLastError() << std::endl;
        return false;
    }

    return true;
}
void Injector::printFromPipe() {
    while (true) {
        std::string message;
        if (readFromPipe(message)) {
            std::cout <<  message << std::endl;
            FlushFileBuffers(hPipe);
        }
        Sleep(100); 
    }
}
void Injector::findID() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    int pid = 0;
    BOOL hResult;
    char dest[100] = { 0 };
    size_t count = 0;
    // Создание снимка всех процессов в системе
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
        std::cout << "Coudln't find pid by name" << std::endl;
        exit(EXIT_FAILURE);
    };
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hResult = Process32First(hSnapshot, &pe32);

    while (hResult) {
        count = wcstombs(dest, pe32.szExeFile, 100);
        if (strcmp(procName, dest) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
        memset(dest, 0x00, count);
        hResult = Process32Next(hSnapshot, &pe32);
    }
    if (pid == 0) {
        std::cout << "Coudln't find pid by name" << std::endl;
        exit(EXIT_FAILURE);
    }
    CloseHandle(hSnapshot);
    
    
    this->processId = pid;
}

