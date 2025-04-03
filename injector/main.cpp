#include "injector.h"
#include <iostream>
#include <Windows.h>

Injector injector;


void parseArgs(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp("-name", argv[i]) && i + 1 < argc) {
            injector.setProcName(argv[i + 1]);
            injector.findID();
        }
        else if (!strcmp("-func", argv[i]) && i + 1 < argc) {
            injector.setFuncName(argv[i + 1]);
            injector.setMode("0");
        }
        else if (!strcmp("-pid", argv[i]) && i + 1 < argc) {
            std::cout << "PID - " << argv[i + 1] << std::endl;
            injector.setProcessID(atoi(argv[i + 1]));
        }
        else if (!strcmp("-hide", argv[i]) && i + 1 < argc) {
            injector.setMode("1");
            injector.setFileName(argv[i + 1]);
        }
    }
}

int main(int argc, char** argv) {
    std::cout << "IN main" << std::endl;
    if (argc < 3) {
        std::cout << "Not enough args!" << std::endl;

    }
    else {
        std::cout << "Parsing!" << std::endl;
        parseArgs(argc, argv);
        injector.createPipe();
        injector.inject();
        injector.connectPipe();
        injector.writeToPipe(injector.getMode());
        if (injector.getMode() == "0")
            injector.writeToPipe(injector.getFuncName());
        else
            injector.writeToPipe(injector.getFileName());
        injector.printFromPipe();
    }
}