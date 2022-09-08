# -*- coding: utf-8 -*-  #
from tkinter import *
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from analyse import *
from tkinter import messagebox
import tkinter.filedialog 

###var globale 
dict_b_f=dict()#dictionnaire ayant pour cle le bouton pour valeur la valid frame
#creer la fentere tkinter
window = Tk()
window.title("L'analyseur de réseau BabyShark")
window.geometry("700x500")
##creer un frame principale
main_frame = LabelFrame(window, text="Trames du fichier",font=("Helvetica",16))
main_frame.pack(fill=BOTH, expand=1)
#creer un canvas
my_canvas = Canvas(main_frame)
##creer un menu
menubar=Menu(window)
window.config(menu=menubar,bg="white")
##creer les frames pour ajouter des boutons
frame_container=Frame(window)
frame_container.pack( fill=X)
#create a canvas inside the frame container
#my_canvas = Canvas(main_frame)
my_canas=Canvas(main_frame, width=150, height=40, bd=0, highlightthickness=0, relief='ridge')
my_canvas.pack(side=LEFT,fill=BOTH,expand=1)
#add a scrollbar to the canvas
my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
my_scrollbar.pack(side=RIGHT, fill=Y)
#configure the canvas
my_canvas.configure(yscrollcommand=my_scrollbar.set)
my_canvas.bind('<Configure>',lambda e:my_canvas.configure(scrollregion= my_canvas.bbox("all")))
#create an other frame inside the canvas
second_frame= LabelFrame(my_canvas, text="", font=("Helvetica",12))
second_frame.pack(fill=BOTH)
#add the new frame to a window in the canvas 
my_canvas.create_window((0,0),window=second_frame,anchor="nw")
#ajouter du style
style=ttk.Style()
style.theme_use("alt")
###creer une deuxieme trame pour affichier l'analyse
fr_analyse=LabelFrame(window,text="",font=("Helvetica",14))#on decale de 210 car la taile de notre frame_contrainer est 200
fr_analyse.pack(fill=BOTH, expand=1, pady=3)

##########la fonction permettant d'analyser######################
def analyse(event): 
    texte_bouton=event.widget.cget("text")#recuperer le bouton cliqué
    valid_frame=dict_b_f[texte_bouton]#on recupere la trame
    liste_analyse=frameAnalyser(valid_frame)#la liste contenant l'analyse des trame
    #####il faut  detruire tout ce qu'il y avait dans la frame
    cleanFrame(fr_analyse)
    ##on sauvegarde les analyses dans un fichier res.txt situé dans le meme répértoire que le fichier code
    file_res=open("res.txt","a")#pour chaque nouveau fichier lu on ecrase le precedent
    #créer la barre pour défiler
    verscrlbar1= ttk.Scrollbar(fr_analyse,orient ="vertical")
    verscrlbar1.pack(side =RIGHT, fill =Y)
    #créer l'arborescence'a
    tree=ttk.Treeview(fr_analyse,yscrollcommand=verscrlbar1.set)
    file_res.write(texte_bouton+"\n")
    tree.pack(fill=BOTH, expand=1)
    f=tree.insert('',0,text=texte_bouton)
    verscrlbar1.config(command=tree.yview)
    for j in range(len(liste_analyse)):
        tmp=liste_analyse[j]
        t=tree.insert(f,j,text=tmp[0])
        file_res.write(tmp[0]+"\n")
        i=0
        for l in tmp[1:]:
            tree.insert(t,i,text=l)
            file_res.write(l+"\n")
            i+=1
    file_res.write("\n\n")
    file_res.close()
    return 
###pour vider la frame############
def cleanFrame(frame):
    for widget in frame.winfo_children():
        widget.destroy()
#########on definit ouvrir()############################
def ouvrir():
    file_name=tkinter.filedialog.askopenfilename(title="Ouvrir",filetypes=[('text files','.txt')]) 
    f=open(file_name,"r")
    ##si le fichier entré par l'utilisateur est viden on affiche un message d'erreur
    if len(f.readlines())==0:
        messagebox.showwarning("Erreur","Fichier vide!")
        f.close()
        return
    f=open(file_name,"r")
    file_res=open("res.txt","w")
    file_res.write("")#on vide le fichier des analyses des fichiers précedents
    file_res.close()
    #on vide la frame d'abord
    cleanFrame(second_frame)
    ###on analyse les trames du fichier selectionne
    list_trame=frameSplitter(f)
    nb_trames=len(list_trame)
    for i in range(nb_trames):
        (valid_frame,ligne_erreur)=frameChecker(list_trame[i])
        if(valid_frame==[]):#si la trame est erronée
            button = Button(second_frame,text="Trame erronée! Erreur à la ligne "+ligne_erreur)
            button.pack()
        else:#si la trame est valide
            IP_Src=".".join(str(int(oct,16)) for oct in valid_frame[26:30])
            IP_Dst=".".join(str(int(oct,16)) for oct in valid_frame[30:34])
            frame_len=str(len(valid_frame)*8)+" octets"
            texte_bouton="Trame "+str(i+1)+"|| Src: "+IP_Src+" => Dst: "+IP_Dst+" ("+frame_len+")"
            # button = Button(frame_container,text=texte_bouton,command=lambda x=i: analyse(valid_frame,x))
            button = Button(second_frame,text=texte_bouton)
            dict_b_f[texte_bouton]=valid_frame
            button.bind("<Button-1>",analyse)
            button.pack(fill=X)
    f.close()
#ajouter une commande pour ouvrir un fichier
menubar.add_command(label="Fichier", command=ouvrir)
menubar.add_command(label="Quitter", command=window.destroy)
window.mainloop()
