#pragma once

#include <iostream>
#include <Windows.h>
#include <string>

#define BYTE_SIZE 13
#define BYTES 8
#define MODE_SIZE 10
#define FUNC_NAME_SIZE 512
#define NUMBER_OF_FUNCTIONS 4
extern "C" uint64_t origFunc;

class Hook
{
private:
    FARPROC targetFunction;
    DWORD oldProtect;
    BYTE oldBytes[BYTE_SIZE];

    BYTE oldBytesMul[NUMBER_OF_FUNCTIONS-1][BYTE_SIZE];
    FARPROC targetFunctionMul[NUMBER_OF_FUNCTIONS-1];

    BYTE jmpBytes[BYTE_SIZE];
    HANDLE hPipe;
    char mode[MODE_SIZE];
    char funcName[FUNC_NAME_SIZE];
    char fileName[FUNC_NAME_SIZE];
    static constexpr const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\MyNamedPipe";
public:
    Hook();
    void setHook(const std::string& funcName, FARPROC addr,int index);
    void unhook(int index);

    bool connectToPipe();
    bool readFromPipe();
    bool writeToPipe(const std::string& message);

    char* getMode();
    char* getFuncName();
    char* getFileName();

};

