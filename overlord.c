#include <windows.h>
#include <stdio.h>

// Déclare un type de fonction correspondant à `Overlord`
typedef void (__stdcall *OverlordFunc)(void);

int main() {
    HMODULE dll_handle = LoadLibrary("malleable_rust_loader.dll");
    if (!dll_handle) {
        printf("Failed to load DLL\n");
        return 1;
    }

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
