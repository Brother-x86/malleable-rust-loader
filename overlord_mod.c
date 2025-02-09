#include <windows.h>
#include <stdio.h>
//#include <unistd.h>

// Déclare un type de fonction correspondant à `Overlord`
typedef void (__stdcall *OverlordFunc)(void);

int main() {
    HMODULE dll_handle = LoadLibrary("loader-2268c72eb6a846ae8f7cd0bff05969ec.dll");
    if (!dll_handle) {
        printf("Failed to load DLL\n");
        return 1;
    }
    //printf("Le programme va dormir pendant 10 secondes...\n");
    //sleep(10);  // Met le programme en pause pendant 10 secondes
    // Obtenez l'adresse de la fonction 'Overlord'
    OverlordFunc Overlord = (OverlordFunc)GetProcAddress(dll_handle, "Overlord");
    if (!Overlord) {
        printf("Failed to find 'Overlord' in DLL\n");
        FreeLibrary(dll_handle);
        return 1;
    }

    // Appelez la fonction
    printf("Calling 'Overlord'...\n");
    Overlord();
    printf("'Overlord' was called successfully.\n");

    FreeLibrary(dll_handle);
    return 0;
}
