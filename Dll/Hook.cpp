#include "pch.h"
#include "Hook.h"

extern "C" uint64_t origFunc = NULL;

Hook::Hook() : targetFunction(nullptr), oldProtect(0) {
    memset(oldBytes, 0, BYTE_SIZE);
    memset(jmpBytes, 0, BYTE_SIZE);
    memset(funcName, 0, FUNC_NAME_SIZE);
    memset(mode, 0, MODE_SIZE);
}

char* Hook::getMode(){
    return mode;
}

char* Hook::getFuncName() {
    return funcName;
}

char* Hook::getFileName() {
    return fileName;
}

bool Hook::connectToPipe() {
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }

    hPipe = CreateFile(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
        return false;
    }

    return true;
}
bool Hook::readFromPipe() {
    if (hPipe == INVALID_HANDLE_VALUE) return false;

    DWORD bytesRead;
    BOOL success = ReadFile(
        hPipe,
        this->mode,
        sizeof(this->mode) - 1,
        &bytesRead,
        NULL);

    if (!success || bytesRead == 0) {
        return false;
    }

    mode[bytesRead] = '\0';
    if (atoi(mode) == 0) {
        success = ReadFile(
            hPipe,
            this->funcName,
            sizeof(this->funcName) - 1,
            &bytesRead,
            NULL);

        if (!success || bytesRead == 0) {
            return false;
        }
        funcName[bytesRead] = '\0';
    }
    else {
        success = ReadFile(
            hPipe,
            this->fileName,
            sizeof(this->fileName) - 1,
            &bytesRead,
            NULL);

        if (!success || bytesRead == 0) {
            return false;
        }
        fileName[bytesRead] = '\0';
    }
    return true;
}

bool Hook::writeToPipe(const std::string& message) {
    if (hPipe == INVALID_HANDLE_VALUE) return false;

    DWORD bytesWritten;
    BOOL success = WriteFile(
        hPipe,
        message.c_str(),
        static_cast<DWORD>(message.size()),
        &bytesWritten,
        NULL);

    if (!success || bytesWritten != message.size()) {
        return false;
    }

    return true;
}

void Hook::setHook(const std::string& funcName, FARPROC addr, int index) {
    HMODULE kernelModule = GetModuleHandleW(L"kernel32.dll");
    if (!kernelModule) {
        writeToPipe("Can't find kernel module!");
        return;
    }

    BYTE tempJMP[BYTE_SIZE] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE2
    };

    
    memcpy(jmpBytes, tempJMP, BYTE_SIZE);
    if (index == 0) {
        targetFunction = GetProcAddress(kernelModule, funcName.c_str());
        if (!targetFunction) {
            writeToPipe("Can't find function address!");
            return;
        }

        VirtualProtect((LPVOID)targetFunction, BYTE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);

        memcpy(oldBytes, targetFunction, BYTE_SIZE);
        uint32_t offset = *(uint32_t*)(oldBytes + 2);
        origFunc = offset + 6;

        FARPROC original_function_address = nullptr;
        uint8_t* func_bytes = (uint8_t*)targetFunction;
        memcpy(&original_function_address, func_bytes + origFunc, 8);

        *(uint64_t*)(tempJMP + 2) = (uint64_t)original_function_address;

        uint64_t trampoline_addr = (uint64_t)VirtualAlloc(
            NULL,
            BYTE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        origFunc = trampoline_addr;
        memcpy((void*)trampoline_addr, tempJMP, BYTE_SIZE);

        memcpy(jmpBytes + 2, &addr, BYTES);
        memcpy(targetFunction, jmpBytes, BYTE_SIZE);
        VirtualProtect((LPVOID)targetFunction, BYTE_SIZE, oldProtect, &oldProtect);

    }
    else {
        targetFunctionMul[index - 1] = GetProcAddress(kernelModule, funcName.c_str());
        if (!targetFunctionMul[index-1]) {
            writeToPipe("Can't find function address!");
            return;
        }
        VirtualProtect((LPVOID)targetFunctionMul[index-1], BYTE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);

        memcpy(oldBytesMul[index - 1], targetFunctionMul[index - 1], BYTE_SIZE);
        memcpy(jmpBytes + 2, &addr, BYTES);

        memcpy(targetFunctionMul[index-1], jmpBytes, BYTE_SIZE);
        VirtualProtect((LPVOID)targetFunctionMul[index-1], BYTE_SIZE, oldProtect, &oldProtect);
    }   
}


void Hook::unhook(int index) {
        DWORD tempProtect;
        if(index == 0)
        {
            if (!targetFunction) return;
            if (VirtualProtect((LPVOID)targetFunction, BYTE_SIZE, PAGE_EXECUTE_READWRITE, &tempProtect)) {
                memcpy(targetFunction, oldBytes, BYTE_SIZE);
                VirtualProtect((LPVOID)targetFunction, BYTE_SIZE, tempProtect, &tempProtect);
            }
        }
        else 
        {
            if (!targetFunctionMul[index - 1]) {
                return;
            }
            if (VirtualProtect((LPVOID)targetFunctionMul[index-1], BYTE_SIZE, PAGE_EXECUTE_READWRITE, &tempProtect)) {
                memcpy(targetFunctionMul[index-1], oldBytesMul[index-1], BYTE_SIZE);
                VirtualProtect((LPVOID)targetFunctionMul[index-1], BYTE_SIZE, tempProtect, &tempProtect);
            }
        }
}

