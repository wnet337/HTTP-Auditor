# Liste des imports nécessaires pour le script
import os
import sys
import webbrowser
import urllib3
import requests

# Désactivation des alertes liées aux certificats SSL/TLS 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration des couleurs pour le terminal
DARK_BLUE = '\033[38;2;10;20;40m'
DARK_BLUE_BOLD = '\033[1;38;2;10;20;40m'
METAL_BLUE_BOLD = '\033[1;38;2;0;191;255m'

C_GREEN = '\033[38;5;46m'
C_YELLOW = '\033[38;5;226m'
C_ORANGE = '\033[38;5;208m'
C_RED = '\033[38;5;196m'

RESET = '\033[0m'

# Liste des en-têtes de sécurité
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'risk': 2, 
        'name': 'HSTS',
        'desc': "Oblige le navigateur à ne communiquer qu'en HTTPS (sécurisé). S'il est absent, un pirate peut forcer le site en HTTP normal pour intercepter les mots de passe ou les données."
    },
    'Content-Security-Policy': {
        'risk': 2, 
        'name': 'CSP',
        'desc': "C'est le gardien du contenu. Il définit d'où le site a le droit de charger des scripts. Sans lui, un attaquant peut injecter un script virus directement sur la page (Attaque XSS)."
    },
    'X-Frame-Options': {
        'risk': 2, 
        'name': 'X-Frame',
        'desc': "Interdit aux autres sites internet d'encadrer (iframe) ta page web. Sans ça, on peut faire du 'Clickjacking' : piéger l'utilisateur pour qu'il clique sur un bouton invisible."
    },
    'X-Content-Type-Options': {
        'risk': 1, 
        'name': 'MIME-Sniff',
        'desc': "Empêche le navigateur de 'deviner' le format d'un fichier. Si un hacker envoie un script malveillant déguisé en fausse image, cet en-tête bloque son exécution."
    },
    'Referrer-Policy': {
        'risk': 1, 
        'name': 'Referrer',
        'desc': "Protège la vie privée. Sans cet en-tête, quand on clique sur un lien, l'URL complète (qui contient parfois des jetons de connexion secrets) fuite vers le site de destination."
    },
    'Permissions-Policy': {
        'risk': 1, 
        'name': 'Perm-Policy',
        'desc': "Désactive l'accès aux API du navigateur (Caméra, Micro, Géolocalisation GPS) si le site n'en a pas besoin, évitant ainsi d'espionner l'utilisateur à son insu."
    }
}


# Gestion du terminal et des entrées utilisateur 
class TerminalMenu:
    
    @staticmethod
    def get_key():
        if os.name == 'nt':
            import msvcrt
            key = msvcrt.getch()
            if key in (b'\x00', b'\xe0'):
                special = msvcrt.getch()
                if special == b'H': return 'UP'
                if special == b'P': return 'DOWN'
            elif key in (b'\r', b'\n'):
                return 'ENTER'
            return None
        else:
            import tty, termios
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                ch = sys.stdin.read(1)
                if ch == '\x1b':
                    sys.stdin.read(1)
                    opt = sys.stdin.read(1)
                    if opt == 'A': return 'UP'
                    if opt == 'B': return 'DOWN'
                elif ch in ('\r', '\n'):
                    return 'ENTER'
                elif ch == '\x03': 
                    sys.exit(0)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return None

    @staticmethod
    def clear():
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{METAL_BLUE_BOLD}GitHub.com/wnet337{RESET}\n")

    @staticmethod
    def show(options, title=""):
        current_idx = 0
        while True:
            TerminalMenu.clear()
            if title:
                print(f"{DARK_BLUE_BOLD}{title}{RESET}\n")
            
            for i, opt in enumerate(options):
                if i == current_idx:
                    print(f"{DARK_BLUE_BOLD}> {opt}{RESET}")
                else:
                    print(f"{DARK_BLUE}  {opt}{RESET}")
            
            key = TerminalMenu.get_key()
            if key == 'UP' and current_idx > 0:
                current_idx -= 1
            elif key == 'DOWN' and current_idx < len(options) - 1:
                current_idx += 1
            elif key == 'ENTER':
                return current_idx

# Classe de gestion et visuel ASCII
class HTTPScanner:
    
    def validate_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def get_ascii_circle(self, score, color):
        """Dessine un cercle ASCII texturé inspiré de la référence visuelle"""
        s = f"{score:02d}"
        return f"""
{color}                . .  .   .  .
           .  . - - - - - - - .  .
         .  - - x x x x x x x - -  .
        . - x x x x x x x x x x x - .
       . - x x x               x x x - .
       . - x x                   x x - .
       . - x x       {s}/10       x x - .
       . - x x                   x x - .
       . - x x x               x x x - .
        . - x x x x x x x x x x x - .
         .  - - x x x x x x x - -  .
           .  . - - - - - - - .  .
                . .  .   .  .{RESET}
"""

    def run(self, url):
        url = self.validate_url(url)
        print(f"\n{DARK_BLUE}Scan en cours : {url}...{RESET}")
        
        try:
            response = requests.get(url, verify=False, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{DARK_BLUE_BOLD}Erreur réseau : {e}{RESET}")
            return

        headers = response.headers
        present = []
        missing = []
        risk_score = 1

        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                present.append({'name': header, 'short': info['name']})
            else:
                risk_score += info['risk']
                missing.append({'name': header, 'short': info['name'], 'desc': info['desc']})

        risk_score = min(10, risk_score)

        if risk_score <= 2:
            color = C_GREEN
        elif risk_score <= 5:
            color = C_YELLOW
        elif risk_score <= 8:
            color = C_ORANGE
        else:
            color = C_RED

        TerminalMenu.clear()
        print(f"{DARK_BLUE_BOLD}Cible : {url}{RESET}")
        
        print(self.get_ascii_circle(risk_score, color))

        print(f"{DARK_BLUE_BOLD}[ > ] Afficher les détails des en-têtes ? (o/n) : {RESET}", end="")
        ans = input().lower().strip()

        if ans in ['o', 'oui', 'y']:
            self.print_report(present, missing)

    def print_report(self, present, missing):
        print(f"\n{DARK_BLUE_BOLD}--- DÉTAILS DE L'ANALYSE ---{RESET}\n")

        print(f"{DARK_BLUE_BOLD}En-têtes Sécurisés Trouvés (Protections actives) :{RESET}")
        if not present:
            print(f"{DARK_BLUE}  Aucune protection majeure détectée.{RESET}")
        else:
            for item in present:
                print(f"{C_GREEN}  [+] {item['name']} ({item['short']}){RESET}")

        print(f"\n{DARK_BLUE_BOLD}En-têtes Manquants (Vulnérabilités potentielles) :{RESET}")
        if not missing:
            print(f"{DARK_BLUE}  C'est parfait, tout est protégé.{RESET}")
        else:
            for item in missing:
                print(f"{C_RED}  [-] {item['name']} ({item['short']}){RESET}")
                print(f"{DARK_BLUE}      Explication : {item['desc']}{RESET}\n")


# Point d'entrée du script 
def main():
    menu_options = [
        "GitHub",
        "OpenSource",
        "Lancer",
        "Quitter"
    ]

    while True:
        choice = TerminalMenu.show(menu_options, title="Menu Principal")
        
        if choice == 0:
            TerminalMenu.clear()
            webbrowser.open("https://github.com/wnet337")
        
        elif choice == 1:
            TerminalMenu.clear()
            try:
                with open(__file__, 'r', encoding='utf-8') as f:
                    print(f"{DARK_BLUE}{f.read()}{RESET}")
            except Exception as e:
                print(f"{DARK_BLUE_BOLD}Erreur : {e}{RESET}")
            input(f"\n{DARK_BLUE_BOLD}Entree...{RESET}")
            
        elif choice == 2:
            TerminalMenu.clear()
            url = input(f"{DARK_BLUE_BOLD}URL : {RESET}")
            if url.strip():
                scanner = HTTPScanner()
                scanner.run(url)
            input(f"\n{DARK_BLUE_BOLD}Appuyez sur Entrée pour revenir au menu...{RESET}")
            
        elif choice == 3:
            TerminalMenu.clear()
            sys.exit(0)

if __name__ == "__main__":
    main()
