import sys
import re
import os

# TODO faire un argparse

def charger_motifs(nom_fichier):
    """Charge les regex ligne par ligne sans les combiner."""
    if not os.path.exists(nom_fichier):
        return []
    with open(nom_fichier, 'r') as f:
        # On garde les lignes individuelles converties en bytes
        return [l.strip().encode('utf-8') for l in f.readlines() if l.strip()]

def nettoyer_pe_rs():
    if len(sys.argv) < 2:
        print("Usage: python script.py <mon_executable.exe>")
        return

    fichier_entree = sys.argv[1]
    fichier_sortie = fichier_entree + ".clean.exe"
    nom_regex = 'remove.regex'

    if not os.path.exists(fichier_entree):
        print(f"❌ Erreur : '{fichier_entree}' introuvable.")
        return

    try:
        with open(fichier_entree, 'rb') as f:
            data_nettoyee = f.read()

        motifs = charger_motifs(nom_regex)
        if not motifs:
            print(f"⚠️ Le fichier {nom_regex} est vide ou introuvable.")
            return

        total_trouves = 0
        print(f"--- Début du nettoyage par passes successives ---")

        # PASSES SUCCESSIVES
        for motif_byte in motifs:
            try:
                # On compile chaque motif du fichier
                regex = re.compile(motif_byte)
                # On trouve toutes les occurrences pour ce motif précis
                occurrences = regex.findall(data_nettoyee)
                
                if occurrences:
                    print(f"[*] Motif [{motif_byte.decode(errors='ignore')}]: {len(occurrences)} trouvés")
                    for match in set(occurrences): # set() pour éviter de remplacer 2 fois la même chaine
                        # ici le debug, TODO faire une option debug pour afficher tout ce qui saute.
                        #print(f"[-] Masquage de : {match.decode(errors='ignore')}")
                        # Remplacement par des null bytes de même longueur (critique pour les offsets PE)
                        remplacement = b'\x00' * len(match)
                        data_nettoyee = data_nettoyee.replace(match, remplacement)
                        total_trouves += 1
            except re.error as e:
                print(f"❌ Erreur dans la regex '{motif_byte.decode()}': {e}")

        if total_trouves > 0:
            with open(fichier_sortie, 'wb') as f:
                f.write(data_nettoyee)
            print(f"\n✅ Terminé ! {total_trouves} segments masqués au total.")
            print(f"📁 Sortie : {fichier_sortie}")
        else:
            print("⚠️ Aucun motif n'a matché dans le fichier.")

    except Exception as e:
        print(f"❌ Erreur fatale : {e}")

if __name__ == "__main__":
    nettoyer_pe_rs()
