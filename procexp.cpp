#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <sddl.h>

// HANDLE is just a Windows thing for a reference to some kernel object
// Here we're given a handle to an already opened token and we want to find out its integrity level.
const char* GetIntegrityLevel(HANDLE hToken) {
    DWORD sz = 0;

    // GetTokenInformation is a two-call pattern. First call with a NULL buffer
    // just tells us how many bytes we need to allocate. Second call fills it.
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &sz);

    TOKEN_MANDATORY_LABEL* pTIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(0, sz);
    if (!pTIL || !GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, sz, &sz))
        return "Unknown";

    // The integrity level is encoded as a SID. The actual level value (RID)
    // sits in the last element of the SID's sub-authority array.
    // We compare it against Windows-defined constants to get a label.
    DWORD rid = *GetSidSubAuthority(pTIL->Label.Sid,
        *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
    LocalFree(pTIL);

    if (rid < SECURITY_MANDATORY_LOW_RID)    return "Untrusted";
    if (rid < SECURITY_MANDATORY_MEDIUM_RID) return "Low";
    if (rid < SECURITY_MANDATORY_HIGH_RID)   return "Medium";
    if (rid < SECURITY_MANDATORY_SYSTEM_RID) return "High";
    return "System";
}

// To find a process's parent we take a snapshot of all running processes,
// which gives us a list of PROCESSENTRY32 structs, each containing a PID
// and its parent PID. We just walk that list until we find our target.
DWORD GetParentPID(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) }; // dwSize must be set before first use
    DWORD parent = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) { parent = pe.th32ParentProcessID; break; }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap); // always close handles when done, same as fclose()
    return parent;
}

// A token holds a list of privileges (things the process is allowed to do
// at the OS level, like shutting down the machine or debugging other processes).
// Each privilege can exist on the token but still be disabled, so we check
// the SE_PRIVILEGE_ENABLED attribute before printing.
void PrintPrivileges(HANDLE hToken) {
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &sz);

    TOKEN_PRIVILEGES* pTP = (TOKEN_PRIVILEGES*)LocalAlloc(0, sz);
    if (!pTP || !GetTokenInformation(hToken, TokenPrivileges, pTP, sz, &sz)) return;

    printf("\n[*] Enabled Privileges:\n");
    for (DWORD i = 0; i < pTP->PrivilegeCount; i++) {
        if (!(pTP->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) continue;
        char name[256] = { 0 };
        DWORD namesz = sizeof(name);
        // Privileges are identified internally by a LUID (locally unique ID).
        // LookupPrivilegeNameA converts that to a readable string like "SeDebugPrivilege".
        LookupPrivilegeNameA(NULL, &pTP->Privileges[i].Luid, name, &namesz);
        printf("    [+] %s\n", name);
    }
    LocalFree(pTP);
}

// The token stores the user as a SID (Security Identifier), which is a binary
// blob, not a name. LookupAccountSidA does the translation to domain\username.
void PrintTokenUser(HANDLE hToken) {
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);

    TOKEN_USER* pTU = (TOKEN_USER*)LocalAlloc(0, sz);
    if (!pTU || !GetTokenInformation(hToken, TokenUser, pTU, sz, &sz)) return;

    char user[256] = { 0 }, domain[256] = { 0 };
    DWORD usersz = sizeof(user), domsz = sizeof(domain);
    SID_NAME_USE use;

    if (LookupAccountSidA(NULL, pTU->User.Sid, user, &usersz, domain, &domsz, &use))
        printf("[*] User         : %s\\%s\n", domain, user);

    LocalFree(pTU);
}

// PPL (Protected Process Light) is a kernel-level protection that restricts
// which processes can open a handle to the protected one. We query it via
// NtQueryInformationProcess, an undocumented ntdll function, so we have to
// resolve it manually with GetProcAddress instead of linking against it directly.
// Class 61 returns a single byte representing the PS_PROTECTION structure.
void PrintProtectionLevel(HANDLE hProcess) {
    typedef NTSTATUS(WINAPI* NtQIP_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    NtQIP_t NtQIP = (NtQIP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQIP) return;

    BYTE info = 0; ULONG ret = 0;
    if (NtQIP(hProcess, 61, &info, sizeof(info), &ret) != 0) {
        printf("[*] PPL Protected: query failed\n");
        return;
    }

    // The byte is bit-packed: lower 3 bits are the protection type,
    // upper 4 bits are the signer level (who signed the binary).
    BYTE type   = info & 0x7;
    BYTE signer = (info >> 4) & 0xF;

    if (!type) { printf("[*] PPL Protected: No\n"); return; }

    const char* signers[] = { "?", "Authenticode", "CodeGen", "Antimalware",
                               "Lsa", "Windows", "WinTcb" };
    printf("[*] PPL Protected: Yes (%s / %s)\n",
        type == 1 ? "PPL" : "PP",
        signer < 7 ? signers[signer] : "Unknown");
}

int main(int argc, char* argv[]) {
    if (argc != 2) { printf("Usage: pinspect.exe <PID>\n"); return 1; }

    DWORD pid = (DWORD)atoi(argv[1]);

    // OpenProcess asks the kernel for a handle to the target process.
    // We specify exactly what we want to do with it via the access mask.
    // The kernel checks our token against the target's security descriptor
    // and either grants the handle or denies it.
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess failed (PID %lu, err %lu)\n", pid, GetLastError());
        return 1;
    }

    DWORD session = 0;
    ProcessIdToSessionId(pid, &session);

    printf("[*] PID          : %lu\n", pid);
    printf("[*] Parent PID   : %lu\n", GetParentPID(pid));
    printf("[*] Session ID   : %lu\n", session);
    PrintProtectionLevel(hProc);

    // Now we open a handle specifically to the process's access token.
    // TOKEN_QUERY is enough to read everything we need from it.
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed (err %lu)\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    PrintTokenUser(hToken);
    printf("[*] Integrity    : %s\n", GetIntegrityLevel(hToken));
    PrintPrivileges(hToken);

    CloseHandle(hToken);
    CloseHandle(hProc);
    return 0;
}
