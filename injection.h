# pragma once
# include <stdio.h>
# include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_NON_DIRECTORY_FILE        0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT   0x00000020

//----------------------------------------------------------------------

# define yapBad(msg, ...) printf("[*-*] " msg "\n", __VA_ARGS__)
# define yapInfo(msg, ...) printf("['-'] " msg "\n", __VA_ARGS__)
# define yapOkay(msg, ...) printf("[+-+] " msg "\n", __VA_ARGS__)

//----------------------------------------------------------------------

BOOL ShellcodeInjection(ULONG_PTR PID, char* filename);
ULONG_PTR findHandle(char* procName);