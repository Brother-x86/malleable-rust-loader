#include <windows.h>
#include <stdio.h>
#include <unistd.h>

// Déclare un type de fonction correspondant à `Overlord`
typedef void (__stdcall *OverlordFunc)(void);

int main() {
    printf("LoadLibrary\n");
    sleep(1);
    HMODULE dll_handle = LoadLibrary("REPLACEME");
    if (!dll_handle) {
        printf("Failed to load DLL\n");
        return 1;
    }
    //printf("Le programme va dormir pendant 10 secondes...\n");
    //sleep(10);  // Met le programme en pause pendant 10 secondes
    for (int i = 0; i < 10; i++) {
        printf("sleep en c\n");
        sleep(1); // Pause de 1 seconde
    }
    // Obtenez l'adresse de la fonction 'Overlord'
    OverlordFunc Overlord = (OverlordFunc)GetProcAddress(dll_handle, "Krang");
    if (!Overlord) {
        printf("Failed to find 'Krang' in DLL\n");
        FreeLibrary(dll_handle);
        return 1;
    }

    // Appelez la fonction
    printf("Calling 'Krang'...\n");
    Overlord();
    printf("'Krang' was called successfully.\n");

    FreeLibrary(dll_handle);
    return 0;
}
