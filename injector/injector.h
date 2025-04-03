#pragma once
#pragma once

#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <string>
class Injector {
public:
	DWORD processId;
	const char* procName;
	HANDLE hPipe;
	std::string mode;
	std::string funcName;
	std::string fileName;
	const char* dllName = "E:\\labs\\ÒÐÑÏÎ\\lab_1\\Dll\\x64\\Debug\\Dll.dll";


	Injector();
	~Injector();

	void setProcName(const char* name);
	void setProcessID(DWORD id);
	void setMode(std::string mode);
	void setFuncName(std::string funcName);
	void setFileName(std::string fileName);


	const char* getProcName();
	DWORD getProcessID();
	std::string getFuncName();
	std::string getMode();
	std::string getFileName();

	void inject();
	void findID();
	void createPipe();
	void connectPipe();
	bool readFromPipe(std::string& message);
	bool writeToPipe(const std::string& message);
	void printFromPipe();
};
