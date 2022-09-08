------------------------------------------------------------------------------------------------------------------------------
                                                            README
------------------------------------------------------------------------------------------------------------------------------

Le code source de notre programme BabyShark est sur deux fichiers:
-Le fichier "projet.py" ou on a des fonctions qui font l'analyse des trames
-Le fichier "test.py" contenant le code source pour l'interface graphique faisant appel aux fonctions codées dans le fichier "projet.py"

I- Dans le fichier "projet.py" on a les fonctions suivantes : 

    - frameSplitter(file): prenant en argument un fichier texte contenant une ou plusieurs trames. Cette fonction sert à séparer les trames de
    notre fichier "file" et à stocker chaque trame dans une liste. Elle renvoie une liste contenant les trames du fichier
    (toute ligne commençant par un offset à zéro annonce le début d'une nouvelle trame).

    - frameChecker(frame): prenant en argument une liste contenant les lignes d'une trame qui sont chaqu'une stockée dans une liste de mots separés par un espace.
    Cette fonction vérifie que chaque ligne commence bien par un offset qui représente un chiffre hexadécimal codé sur plus de deux chiffres.
    Ensuite, on parcourt cette liste et on supprime toutes les valeurs textuelles et les chiffres héxadécimaux codés sur plus de deux chiffres qu'ils soient
    au début, milieu, fin de la ligne ou entre les lignes.
    Ensuite, elle vérifie qu'une ligne est bien complète avant de l'ajouter à la trame, c'est à dire le nombre d'octets requis (offset suivant - offset de la ligne actuelle ).
    Dans le cas d'une erreur on renvoie le numéro de la ligne contenant l'erreur pour l'afficher par la suite sur l'interface graphique.

    - frameAnalyser(frame): cette fonction prend argument une trame (après vérification qu'elle est bien valide).
    Elle analyse l'enthete Ethernet, IPV4, UDP, DNS ou DHCP selon le numero de port destination.
    Pour l'enthete IPV4 avec option , on a traité uniquement les six options vues dans le cours pour le reste notre programme affiche un message "Unknown option".
    Notre programme ne traite que les protocols UDP et si la trame en contient un autre il renvoie un message indiquant que le protocole en question n'est pas pris en charge.
    Pour l'enthete DHCP, on a traité les 08 types avec leurs options respectives.
    Pour l'enthete DNS, on a traité les 06 champs d'entete ainsi que les sections Questions, Réponses, Autorités et Additionnelles, et on a décodé leurs
    six types : AAAA, A, CNAME, MX, NS, SOA et ecrit un message "Unknown type" pour les autres types non traités.
    Cette fonction retourne une liste contenant les listes d'analyse de la trame ethernet et les protocoles qu'elle encapsule ([Ethernet,IPV4,UDP,DHCP ou DNS])



II- Dans le fichier "test.py" :
   - On crée une fenetre tkinter qu'on divise en deux frames tkinter, une frame_container et fr_analyse.
   - Cette fenetre contient un menu , et le bouton "Fichier" qui fait appel à la fonction ouvrir().
   - ouvrir() : ouvre une fenetre de dialogue permettant à l'utilisateur de sélectionner le fichier qu'il souhaite analyser. Ensuite, ouvre le fichier en mode lecture 
    et fait appel à la fonction frameSplitter(fichier) qui va lui renvoyer une liste contenant les trames à analyser. On fait une boucle qui parcout cette liste
    et pour chaque trame on vérifie si elle est valide avec la fonction frameChecker(trame). A chaque tour de boucle si la trame est valide, on crée un bouton contenant le numéro de la trame , l'adresse IP source , l'adresse IP destination
    ainsi que la longueur de la trame. Ce bouton sera ajouté à frame_container et fera appel à la fonction analyse() dès que l'utilisateur aura cliqué dessus.
    On stockera les trames dans un dictionnaire qui associe le texte d'un bouton à la trame qu'il lui correspond.
    Par contre, si la trame lu est erronée on aura un bouton indiquant cela ainsi que la ligne de l'erreur.
   - Une fois qu'on a cliqué sur un bouton , on enclenche la fonction analyse(event). Cette fonction prend en argument event qui est le bouton séléctionné, 
    on récupere via la dictionnaire la trame qui lui est associée et on l'analyse en faisant appel à la fonction frameAnalyser(trame).
    Le résultat de l'analyse sera ajouté à la frame tkinter fr_analyse sous forme arborescente (chaque entete pourra etre réduite et développée). 
   - Les trames seront analysées selon l'ordre de séléction de l'utilisateur (bouton selectionné).
   - A chaque fois qu'une trame est analysée , une copie de l'analyse sera enregistrée dans le fichier "res.txt" du répértoire courant.
    Le fichier écrira les trames selon l'ordre d'analyse que vous aurez choisi en cliquant sur les boutons.


    