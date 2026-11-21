"""Point d'entrée principal d'ARCHI MONITOR 2.0."""

from cli.menu import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nARCHI MONITOR interrompu par l'utilisateur.")
