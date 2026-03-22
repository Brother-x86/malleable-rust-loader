import sys
import re
import os


def charger_motif(nom_fichier):
    with open(nom_fichier, 'r') as f:
        # Lire les lignes, enlever les espaces/retours à la ligne, ignorer les vides
        lignes = [l.strip() for l in f.readlines() if l.strip()]
    
    # Joindre avec le pipe |
    # On entoure chaque ligne de (?: ) pour isoler les "OU" proprement
    motif_string = "|".join(f"(?:{l})" for l in lignes)
    
    # Retourner en format bytes (rb)
    return motif_string.encode('utf-8')


def nettoyer_pe_rs():
    if len(sys.argv) < 2:
        print("Usage: python script.py <mon_executable.exe>")
        return

    fichier_entree = sys.argv[1]
    fichier_sortie = fichier_entree + ".clean.exe"

    if not os.path.exists(fichier_entree):
        print(f"❌ Erreur : '{fichier_entree}' introuvable.")
        return

    try:
        # Lecture en mode BINAIRE pur
        with open(fichier_entree, 'rb') as f:
            data = f.read()

        # REGEX BINAIRE :
        # [^ \x00-\x1f]{1,100}  -> Caractères imprimables (chemin)
        # (?:[/\\][^ \x00-\x1f]{1,50}){1,7} -> Un séparateur / ou \ suivi de texte, répété MAX 7 fois
        # \.rs                  -> Se termine par .rs
        # On utilise b'' pour chercher dans des bytes
        #motif = rb'[a-zA-Z0-9._\-\\/]+(?:[/\\][a-zA-Z0-9._\-\\/]+){0,6}\.rs'
        #motif = rb'/[a-zA-Z0-9._\-]+/[a-zA-Z0-9._\-]+/[a-zA-Z0-9._\-]+/[a-zA-Z0-9._\-]+/[a-zA-Z0-9._\-]+\.rs'
        #motif = rb'(?:[/\\][a-zA-Z0-9._\-]+){1,5}\.rs|\.cargo/registry/src/index\.crates\.io-[a-z0-9]+/[a-zA-Z0-9._\-]+/src|/home/user/|\.cargo/registry|loader::[a-z0-9_]|\.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib'

        #motif = rb'(?:[/\\][a-zA-Z0-9._\-]+){1,5}\.rs|\.cargo/registry/src/index\.crates\.io-[a-z0-9]+/[a-zA-Z0-9._\-]+/src|/home/user/|\.cargo/registry|loader::[a-z0-9_]|\.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib|struct\s[a-zA-Z0-9]+\swith\s\d+\selements'
        

        #motif = rb'(?:[/\\][a-zA-Z0-9._\-]+){1,5}\.rs|\.cargo/registry/src/index\.crates\.io-[a-z0-9]+/[a-zA-Z0-9._\-]+/src|/home/user/|\.cargo/registry|loader::[a-z0-9_]|\.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib|struct\s[a-zA-Z0-9]+\swith\s\d+\selements'
     
        motif = charger_motif('remove.regex')


        trouves = re.findall(motif, data)

        if trouves:
            print(f"--- Nettoyage de {len(trouves)} chemins (Max 5 niveaux) ---")
            # On remplace chaque chemin par des octets nuls (0x00) de la même longueur
            # pour NE PAS corrompre les offsets du fichier PE.
            data_nettoyee = data
            for chemin in trouves:
                print(f"[-] Masquage de : {chemin.decode(errors='ignore')}")
                # Remplacement par des zones vides (null bytes) pour garder la taille identique
                remplacement = b'\x00' * len(chemin)
                data_nettoyee = data_nettoyee.replace(chemin, remplacement)
            
            # Sauvegarde en binaire
            with open(fichier_sortie, 'wb') as f:
                f.write(data_nettoyee)
            
            print(f"\n✅ Terminé ! L'exécutable devrait toujours fonctionner.")
            print(f"📁 Sortie : {fichier_sortie}")
        else:
            print("⚠️ Aucun chemin correspondant aux critères n'a été trouvé.")

    except Exception as e:
        print(f"❌ Erreur : {e}")

if __name__ == "__main__":
    nettoyer_pe_rs()
