    Prérequis:
     -Python 3
     -Le fichier des trames à analyser doit etre un fichier ".txt"
    Utilisation:
      * Pour lancer le programme BabyShark sur linux vous pouvez:
	  - Soit lancer directement le fichier executable "BabyShark" en double cliquant dessus ou en tapant "./Babyshark" sur le terminal 	dans le répértoire "~/reseau/linux"
	  - Soit taper la commande "make" sur le terminal dans le répértoire "~/reseau/linux" 
      * Pour lancer le programme BabyShark sur mac vous pouvez:
	  - Taper la commande "make" sur le terminal dans le répértoire "~/reseau/mac" 
      * Pour lancer le programme BabyShark sur windows vous pouvez:
      	  - Taper la commande "python3 BabyShark.py" sur le terminal dans le répértoire "~/reseau/windows" 
     - Celui-ci affichera une interface graphique ou vous pouvez cliquer sur le bouton "Fichier" du Menu ensuite le bouton "Ouvrir" qui engendre l'ouverture d'une fenetre ou il'ya tous vos fichiers ".txt". 
       Vous séléctionnez le fichier contenant la ou les trames à analyser et vous cliquez sur le bouton "Ouvrir"
     - Celui-ci affichera des boutons contenant les numéros des trames contenus dans votre fichier.
       Et dans le cas ou une trame n'est pas valide, un bouton "Trame erroné" s'affichera.
     - Cliquer sur le bouton correspondant à la trame valide que vous souhaitez analyser ce qui engendre l'affichage des entêtes de protocole présentés sous forme arborescente qui peuvent etre développées et réduites (en cliquant sur l'icone +)
     - Le résultat d'analyse du fichier sera automatiquement sauvegardé dans le fichier "res.txt" 
     - Pour quitter le programme BabyShark, cliquer sur le bouton "Quitter" du Menu
     - Le fichier "res.txt" sera remis à vide avec les nouveaux résultats de chaque analyse d'un autre fichier ".txt" contenant des trames . 
     - Il est donc conseillé de le déplacer dans un autre répertoire si vous souhaitez conserver les résultats de votre analyse avant une nouvelle réutilisation de l'analyseur.
    
    

