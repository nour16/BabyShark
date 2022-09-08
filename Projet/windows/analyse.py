# -*- coding: utf-8 -*-  #
# -*- coding: utf-8 -*-  #
import numpy as np

def is_hexa(ch):
    """renvoie true si ch est un chiffre hexa décimal"""
    try :
        int(ch,16)
    except:
        return False
    return True

def frameSplitter(file):
    frame_list=[]
    frame=[]
    list_list=[]
    for line in file :        
        if line:
            list_line=[]
            for word in line.split():
                list_line.append(word)#liste des mots d'une ligne
            if(list_line!=[]) and is_hexa(list_line[0])==True:#on n'ajoute pas les lignes vides
                list_list.append(list_line)
    for i in range(len(list_list)-1):
        curr_offset=list_list[i][0]
        next_offset=list_list[i+1][0]
        if(is_hexa(curr_offset) and int(curr_offset,16)==0):
            frame=[]
        elif(is_hexa(next_offset) and int(next_offset,16)==0 ):
            frame_list.append(frame)        
        frame.append(list_list[i])
    #i=len(list_list)-1  :dernière ligne de la trame
    if(len(list_list)!=0):
        offset=list_list[len(list_list)-1][0]
        if(is_hexa(offset) and int(offset,16)==0 ):
            frame=[]   
        frame.append(list_list[len(list_list)-1])
    frame_list.append(frame)#on ajoute la dernière trame
    return frame_list


def frameChecker(frame):
    """
    frame:liste contenant tous les listes d'octets de chaque lignes de la trame
    renvoie un tuple contenant la trame valide sans offset et la chaine contenant le numéro de la ligne erronée """
    list_list=[]
    ligne_erreur="" #va contenir la chaine de caractère representant la ligne d'erreur
    for line in frame:#on verifie que les lignes ont un offset au debut (chiffre hexa decimal>2)
        offset=line[0]
        if (len(offset)>2 and is_hexa(offset)):#on ajoute uniquement les lignes commençant par un offset
            list_list.append(line)#liste contenant les lignes de la trame stockees dans des listes
    for line in list_list:
        for octet in line[1:]:
            if(len(octet)!=2 or (not is_hexa(octet))):
                del line[line.index(octet)]
    #check offset
    taille_tot=(taille_trame(list_list))
    if (taille_tot>=64 and taille_tot<=1500):
        for i in range(len(list_list)-1):
            curr_offset=int(list_list[i][0],16)
            next_offset=int(list_list[i+1][0],16)
            if (len(list_list[i])-1)<(next_offset-curr_offset):#si la ligne est incomplete
                ligne_erreur=str(i+1)
                return ([],ligne_erreur)
            else:
                tmp=list_list[i]
                list_list[i]=tmp[0:(next_offset-curr_offset)+1]
    #on renvoie la trame sans offset et la chaine vide car il n y a pas d'erreur
    valid_frame=[]
    for i in range(len(list_list)):
        del list_list[i][0]
        valid_frame+=list_list[i]
    return (valid_frame,ligne_erreur)#frame without offset


def frameAnalyser(frame):
    analyse=[]
    UDP=[]
    DHCP=[]
    DNS=[]
    #Ethernet
    Ethernet=frame[0:14]
    ad_Dest=":".join(str(oct) for oct in Ethernet[0:6])
    ad_Src=":".join(str(oct) for oct in Ethernet[6:12])
    Type="".join(str(oct) for oct in Ethernet[12:])
    type_name=""
    res_eth=[]
    res_IP=[]
    res_UDP=[]
    res_DHCP=[]
    res_DNS=[]
    #Ethernet
    Ethernet=frame[0:14]
    ad_Dest=":".join(str(oct) for oct in Ethernet[0:6])
    ad_Src=":".join(str(oct) for oct in Ethernet[6:12])
    Type="".join(str(oct) for oct in Ethernet[12:])
    if(Type=='0800'):
        type_name="IPv4"
    ##analyse de l'entete ethernet
    res_eth.append("Ethernet ||, Src: "+("Boadcast" if ad_Src=="ff:ff:ff:ff:ff:ff" else ad_Src)+"("+ad_Src+"), Dst: "+("Boadcast " if ad_Dest=="ff:ff:ff:ff:ff:ff" else ad_Dest)+"("+ad_Dest+")")
    res_eth.append("    Destination: "+("Broadcast" if ad_Dest=="ff:ff:ff:ff:ff:ff" else ad_Dest)+" ("+ad_Dest+")")
    res_eth.append("    Source: "+ad_Src+" ("+ad_Src+")")
    res_eth.append("    Type: "+type_name+" (0x"+Type+")")
    analyse.append(res_eth)
    #protocole IP
    IP=frame[14:34] #*On supposant que IP sans options   
    IHL=IP[0][1] #on extrait la longueur de l'entete IP pour savoir on arrete ou pour IP
    IP=frame[14:14+(int(IHL,16)*4)] #toute l'entete IP
    if(Type=='0800'): 
        Version=int(IP[0][0],16)
        IHL=IP[0][1]
        TOS=IP[1]
        Total_length=IP[2]+IP[3]
        Identification=IP[4]+IP[5]
        Flags=IP[6]
        Flags_binaire=tobin(int(IP[6],16),3) #extraire les 3 bits de flags
        Fragment_offset=IP[6]+IP[7]
        TTL=IP[8]
        Protocol=IP[9]
        if(int(Protocol,16)==17):
            name_protocol="UDP"
        elif(int(Protocol,16)==6): #Juste pour tester la trame!
            name_protocol="TCP"
        elif(int(Protocol,16)==1):
            name_protocol="ICMP"
        else:
            name_protocol="Unknown Protocol"   
        Header_checksum=IP[10]+IP[11]
        Src_ip=".".join(str(int(oct,16)) for oct in IP[12:16])
        Dst_ip=".".join(str(int(oct,16)) for oct in IP[16:20])
        #analyse de IP
        res_IP.append("Internet Protocol Version "+str(Version)+", Src: "+Src_ip+", Dst: "+Dst_ip)
        res_IP.append("    "+tobin(Version,4)+".... = Version: "+str(Version))
        res_IP.append("    ...."+tobin(int(IHL,16),4)+" = Header Length: "+str(int(IHL,16)*4)+" bytes ("+str(int(IHL,16))+")")
        res_IP.append("    Differentiated Services Fieldd: 0x"+TOS+" (DSCP:CS0, ECN: Not-ECT)")
        res_IP.append("    Total Length: "+str(int(Total_length,16)))
        res_IP.append("    Identification: 0x"+Identification+" ("+str(int(Identification,16))+")")
        res_IP.append("    Flags: 0x"+Flags)
        res_IP.append("        "+Flags_binaire[0]+"... .... = Reserved bit: Not set")
        res_IP.append("        ."+Flags_binaire[1]+".. .... = Reserved bit: "+("Not set" if Flags_binaire[1]=='0' else "Set" ))
        res_IP.append("        .."+Flags_binaire[2]+". .... = Reserved bit: "+("Not set" if Flags_binaire[2]=='0' else "Set" ))
        res_IP.append("    ..."+tobin(int(Fragment_offset,16),13)+" = Fragment Offset: "+str(int(Fragment_offset,16)))
        res_IP.append("    Time to Live: "+str(int(TTL,16)))
        res_IP.append("    Protocol: "+name_protocol+" ("+str(int(Protocol,16))+")")
        res_IP.append("    Header Checksum: 0x"+Header_checksum+" [validation disabled]")
        res_IP.append("    [Header Checksum status: Unverified]")
        res_IP.append("    Source Address: "+Src_ip)
        res_IP.append("    Destination Address: "+Dst_ip)
        #il faut verifier s'il y'a des options 
        if(int(IHL,16)*4>20): #si la longueur de l'entète >20 alors IP contient des options
            taille_options=int(IHL,16)*4-20
            Options=IP[20:20+taille_options]
            res_IP.append("    Options: ("+str(taille_options)+" bytes)")
            while(len(Options)>1): #si len(Options)=1 cad on a que le end of options dans la liste!
                Op_type=int(Options[0],16)
                if(Op_type==1):
                    Op_name=get_op_name(Op_type)
                    res_IP.append("        IP Option - "+Op_name)
                    res_IP.append("            Type: "+str(Op_type))
                    Options=Options[1:]
                else:
                    Op_name=get_op_name(Op_type)
                    Op_Length=int(Options[1],16)
                    Op_Valeur=int(Options[2],16)  
                    res_IP.append("        IP Option - "+Op_name+" ("+str(Op_Length)+" bytes)")
                    res_IP.append("            Type: "+str(Op_type))
                    res_IP.append("            Length: "+str(Op_Length))
                    res_IP.append("            Pointer: "+str(Op_Valeur))
                    donnees=Options[3:len(Options)-1]
                    #cas de l'option Record Route
                    if (Op_type==7):#ajouter les routes pour l'option routeOption
                        i=0
                        while(i<len(donnees)):
                            route=".".join(str(int(oct,16)) for oct in donnees[i:i+4])
                            if donnees[i:i+4].count('00')==4:
                                res_IP.append("            Empty Route: "+route)
                            else:
                                res_IP.append("            Recorded Route: "+route)
                            i+=4
                    Options=Options[Op_Length:] #on supprime l'option qu'on a traité
            Op_type=int(Options[0],16)
            Op_name=get_op_name(Op_type)
            res_IP.append("        IP Option - "+Op_name)
            res_IP.append("            Type: "+str(Op_type))
            Options=Options[1:]#on enleve les 02 octets de end on options
            #on verifie s'il y a du padding dans l'entete
            if len(Options)>0 and Options.count("00")==len(Options):
                res_IP.append("    Padding: "+"".join(oct for oct in Options))
        analyse.append(res_IP)
        #analyse UDP
        if(int(Protocol,16)==17):
            ind_fin_ip=14+(int(IHL,16)*4)
            UDP=frame[ind_fin_ip:ind_fin_ip+8] #l'entete Udp est toujours fixe à 8 octets           
            Src_Port=str(int("".join(oct for oct in UDP[0:2]),16))
            Dst_Port=str(int("".join(oct for oct in UDP[2:4]),16))
            Length=str(int("".join(oct for oct in UDP[4:6]),16))
            Checksum=UDP[6]+UDP[7]
            UDP_Payload=frame[ind_fin_ip+8:]
            len_UDP_Payload=len(UDP_Payload)
            res_UDP.append("User Datagram Protocol, Src Port: "+Src_Port+" Dst Port: "+Dst_Port)
            res_UDP.append("    Source Port: "+Src_Port)
            res_UDP.append("    Destination Port: "+Dst_Port)
            res_UDP.append("    Length: "+Length)
            res_UDP.append("    Checksum: 0x"+Checksum+" [unverified]")
            res_UDP.append("    [Checksum Status: Unverified]")
            res_UDP.append("    UDP payload ("+str(len_UDP_Payload)+" bytes)")
            analyse.append(res_UDP)
            #analyse DHCP
            if (int(Dst_Port)==68 or int(Dst_Port)==67): 
                idx_dhcp=len(Ethernet)+len(IP)+8 
                DHCP=frame[idx_dhcp:]
                type_dhcp=str(int(DHCP[0],16))
                hard_type=DHCP[1]
                hard_len=str(int(DHCP[2],16))
                hops=str(int(DHCP[3],16))
                tran_ID="".join(str(oct) for oct in DHCP[4:8])
                elapsed=str(int("".join(str(oct) for oct in DHCP[8:10]),16))
                bootp_flags="".join(str(oct) for oct in DHCP[10:12])
                Flags_binaire=tobin(int(bootp_flags,16),16)
                client_ip=".".join(str(int(oct,16)) for oct in DHCP[12:16])
                ur_add=".".join(str(int(oct,16)) for oct in DHCP[16:20])
                srv_add=".".join(str(int(oct,16)) for oct in DHCP[20:24])
                relay_add=".".join(str(int(oct,16)) for oct in DHCP[24:28])
                client_mac=":".join(str(oct) for oct in DHCP[28:34])
                cli_hard_padding="".join(str(oct) for oct in DHCP[34:43])
                tmp=("".join(str(oct) for oct in DHCP[43:107]))
                if int(tmp,16)==0:
                    srv_host_name= "not given" 
                else :  
                    srv_host_name=bytes.fromhex(("".join(str(oct) for oct in DHCP[43:107]))).decode("ASCII")
                tmp=("".join(str(oct) for oct in DHCP[107:235]))
                if int(tmp,16)==0:
                    boot_file_name="not given"
                else:
                    boot_file_name=bytes.fromhex(("".join(str(oct) for oct in DHCP[107:235]))).decode("ASCII") 
                op_53=DHCP[240:243]
                type_msg=str(int(op_53[2],16))
                len_op_53=op_53[1]
                Op_number=op_53[0]
                if type_msg=="1":
                    res_DHCP.append("Dynamic Host Configuration Protocol (Discover)")
                    res_DHCP.append("   Message type: Boot Request ("+type_dhcp+")")
                elif type_msg=="2":
                    res_DHCP.append("Dynamic Host Configuration Protocol (Offer)")
                    res_DHCP.append("    Message type: Boot Reply ("+type_dhcp+")")
                elif type_msg=="3":
                    res_DHCP.append("Dynamic Host Configuration Protocol (Request)")
                    res_DHCP.append("    Message type: Boot Request("+type_dhcp+")")
                elif type_msg=="4":
                    res_DHCP.append("Dynamic Host Configuration Protocol (Decline)")
                    res_DHCP.append("    Message type: Boot Request"+type_dhcp+")")
                elif type_msg=="5":
                    res_DHCP.append("Dynamic Host Configuration Protocol (ACK)")
                    res_DHCP.append("    Message type: Boot Reply("+type_dhcp+")")
                elif type_msg=="6":
                    res_DHCP.append("Dynamic Host Configuration Protocol (NAK)")
                    res.DHCP.append("    Message type: Boot Reply("+type_dhcp+")")
                elif type_msg=="7":
                    res_DHCP.append("Dynamic Host Configuration Protocol (Release)")
                    res_DHCP.append("    Message type: Boot Reply("+type_dhcp+")")
                elif type_msg=="8":
                    res_DHCP.append("Dynamic Host Configuration Protocol (Inform)")
                    res_DHCP.append("    Message type: Boot Request("+type_dhcp+")")           
                res_DHCP.append("    Hardware type: Ethernet (0x"+hard_type+")")
                res_DHCP.append("    Hardware adress length: "+hard_len)
                res_DHCP.append("    Hops: "+hops)
                res_DHCP.append("    Transaction ID: 0x"+tran_ID)
                res_DHCP.append("    Seconds elapsed: "+elapsed)
                res_DHCP.append("    Bootps flags: "+"0x"+bootp_flags) 
                res_DHCP.append("        "+Flags_binaire[0]+"... .... .... .... = Broadcast flag: Unicast")
                res_DHCP.append("        ."+Flags_binaire[1:]+" = Reserved flags: 0x"+bootp_flags)
                res_DHCP.append("    Client IP address: "+client_ip)
                res_DHCP.append("    Your (client) IP address: "+ur_add)
                res_DHCP.append("    Next server IP server adress: "+srv_add)
                res_DHCP.append("    Relay agent IP address: "+relay_add)
                res_DHCP.append("    Client MAC address: "+client_mac)
                res_DHCP.append("    Client hardware address padding: "+cli_hard_padding)
                res_DHCP.append("    Server host name "+srv_host_name)
                res_DHCP.append("    Boot file name "+boot_file_name)
                if "".join(str(oct) for oct in DHCP[235:240])=="63825363":
                    magic="DHCP" 
                    res_DHCP.append("    Magic cookie: "+magic)
                op_DHCP=DHCP[240:]
                if(len(op_DHCP)!=0):  
                    op_t=int(op_DHCP[0],16) 
                    while op_t!=255:#si on n'est pas arrivée a la fin de l'entete DHCP  
                        len_op=int(op_DHCP[1],16)
                        if(op_t==53):
                            res_DHCP.append("    Option: ("+str(int(Op_number,16))+") DHCP Message Type (Request)")
                            res_DHCP.append("        Length: "+str(int(len_op_53,16)))
                            res_DHCP.append("        DHCP: Request ("+type_msg+")")
                            op_DHCP=op_DHCP[len_op+2:]
                        elif(op_t==116):
                            res_DHCP.append("    Option: ("+str(op_t)+") DHCP Auto-Configuration")
                            res_DHCP.append("        Length: "+str(len_op))
                            res_DHCP.append("        DHCP Auto-Configuration: AutoConfigure ("+str(int(op_DHCP[2],16))+")")
                            op_DHCP=op_DHCP[len_op+2:]
                        elif(op_t==61):
                            res_DHCP.append("    Option: ("+str(op_t)+") Client identifier")
                            res_DHCP.append("        Length: "+str(len_op))
                            res_DHCP.append("        Hardware type: Ethernet (0x"+op_DHCP[2]+")")
                            res_DHCP.append("        Client MAC adress: "+(":".join(str(oct) for oct in op_DHCP[3:len_op+2])))
                            op_DHCP=op_DHCP[len_op+2:]
                        elif(op_t==50):
                            req_ip_adress=(":".join(str(oct) for oct in op_DHCP[2:len_op+2]))
                            res_DHCP.append("    Option: ("+str(op_t)+") Requested IP Address ("+req_ip_adress+")")                
                            res_DHCP.append("        Length: "+str(len_op))
                            res_DHCP.append("        Requested IP Address: "+req_ip_adress)
                            op_DHCP=op_DHCP[len_op+2:]
                        elif(op_t==12):
                            res_DHCP.append("    Option: ("+str(op_t)+") Host Name")
                            res_DHCP.append("        Length: "+str(len_op))
                            host_name=("".join(str(oct) for oct in op_DHCP[2:len_op+2]))
                            host_byte=bytes.fromhex(host_name)
                            res_DHCP.append("       Host Name: "+host_byte.decode("ASCII"))
                            op_DHCP=op_DHCP[len_op+2:]
                        elif(op_t==60):
                            res_DHCP.append("   Option: ("+str(op_t)+") Vendor class identifier")
                            res_DHCP.append("       Length: "+str(len_op))
                            v_c_i=("".join(str(oct) for oct in op_DHCP[2:len_op+2]))
                            v_c_i_byte=bytes.fromhex(v_c_i)
                            res_DHCP.append("       Vendor class identifier: "+v_c_i_byte.decode("ASCII")) 
                            op_DHCP=op_DHCP[len_op+2:]
                        elif(op_t==55):
                            res_DHCP.append("    Option: ("+str(op_t)+") Parameter Request List")
                            res_DHCP.append("        Length: "+str(len_op))
                            k=1
                            for j in range(2,len_op+2):
                                res_DHCP.append("        Parameter Request List Item: ("+str(int(op_DHCP[j],16))+") "+get_op_dhcp(int(op_DHCP[j],16)))
                            op_DHCP=op_DHCP[len_op+2:]
                        elif(op_t==1):
                            mask=".".join(str(int(oct,16)) for oct in op_DHCP[2:len_op+2])
                            res_DHCP.append("    Option: ("+str(op_t)+") Subnet Mask ("+mask+")")
                            res_DHCP.append("        Length: "+str(len_op))
                            res_DHCP.append("        Subnet Mask: "+mask)
                            op_DHCP=op_DHCP[len_op+2:]#on supprime l'option lue
                        elif(op_t==57):
                            res_DHCP.append("    Option: ("+str(op_t)+") Maximum DHCP Message Size")
                            res_DHCP.append("        Length: "+str(len_op))
                            size="".join(str(int(oct,16)) for oct in op_DHCP[2:len_op+2])
                            res_DHCP.append("        Maximum DHCP Message Size: "+str(int(size,16)))
                            op_DHCP=op_DHCP[len_op+2:]#on supprime l'option lue
                        elif(op_t==3):
                            router=".".join(str(int(oct,16)) for oct in op_DHCP[2:len_op+2])
                            res_DHCP.append("    Option: ("+str(op_t)+") Router")
                            res_DHCP.append("        Length: "+str(len_op))
                            res_DHCP.append("        Router: "+router)
                            op_DHCP=op_DHCP[len_op+2:]#on supprime l'option lue
                        elif(op_t==6):
                            res_DHCP.append("    Option: ("+str(op_t)+") Domain Name Server")
                            res_DHCP.append("        Length: "+str(len_op))
                            dns=".".join(str(int(oct,16)) for oct in op_DHCP[2:6])
                            res_DHCP.append("       Domain Name Server: "+dns)
                            dns=".".join(str(int(oct,16)) for oct in op_DHCP[6:len_op+2])
                            res_DHCP.append("       Domain Name Server: "+dns)
                            op_DHCP=op_DHCP[len_op+2:]#on supprime l'option lue
                        elif(op_t==15):
                            dmn=("".join(str(oct) for oct in op_DHCP[2:len_op+2]))
                            dmn_bytes=bytes.fromhex(dmn)
                            res_DHCP.append("    Option: ("+str(op_t)+") Domain Name")
                            res_DHCP.append("        Length: "+str(len_op))
                            res_DHCP.append("        Domain Name: "+dmn_bytes.decode("ASCII"))
                            op_DHCP=op_DHCP[len_op+2:]#on supprime l'option lue
                        elif op_t==51:
                            time=0
                            for t in op_DHCP[2:len_op+2]:
                                time+=int(t,16)
                            res_DHCP.append("    Option: ("+str(op_t)+") IP Adress Lease Time")
                            res_DHCP.append("        Length: "+str(len_op))
                            res_DHCP.append("        IP Adress Lease Time: ("+str(time)+" s) "+(str(time/3600)+" day" if time>36000 else ""))
                            op_DHCP=op_DHCP[len_op+2:]#on supprime l'option lue
                        elif op_t==54:
                            tmp=".".join(str(int(oct,16)) for oct in op_DHCP[2:len_op+2])
                            res_DHCP.append("    Option: ("+str(op_t)+") DHCP Server Identifier ("+tmp+")")
                            res_DHCP.append("        Length: "+str(len_op))
                            res_DHCP.append("        DHCP Server Identifier: "+tmp)
                            op_DHCP=op_DHCP[len_op+2:]#on supprime l'option lue     
                        elif op_t==81:
                            res_DHCP.append("    Option: ("+str(op_t)+") Client Fully Qualified Domain Name")
                            res_DHCP.append("        Length: "+str(len_op))
                            res_DHCP.append("        flags: 0x"+str(int(op_DHCP[2],16)))
                            fla_bin=tobin(int(op_DHCP[2],16),8)
                            res_DHCP.append("           "+fla_bin[:4]+" .... = Reserved flags: 0x"+fla_bin[:4])
                            res_DHCP.append("           .... "+fla_bin[4]+"... = Server DDNS: Some server updates")
                            res_DHCP.append("           .... "+fla_bin[5]+".. = Encoding: ASCII encoding")
                            res_DHCP.append("           .... "+fla_bin[6]+". = Server overrides: "+"No override" if fla_bin[6]=="0" else "override")
                            res_DHCP.append("           .... "+fla_bin[7]+" = Server: "+"Client" if fla_bin[7]=="0" else "Server")
                            res_DHCP.append("        A-RR result: "+str(int(op_DHCP[3])))
                            res_DHCP.append("        PTR-RR result: "+str(int(op_DHCP[4])))
                            client=("".join(str(oct) for oct in op_DHCP[4:len_op+2]))
                            client_bytes=bytes.fromhex(client)
                            res_DHCP.append("        Client name: "+client_bytes.decode("ASCII"))
                            op_DHCP=op_DHCP[len_op+2:]#on supprime l'option lue 
                        else:
                            res_DHCP.append("    Option: Unknonw option")
                            op_DHCP=op_DHCP[len_op+2:]#on supprime l'option lue  
                        op_t=int(op_DHCP[0],16)
                    if(op_t==255):
                        res_DHCP.append("    Option: ("+str(op_t)+") End")
                        res_DHCP.append("        Option End: "+str(op_t))
                        op_DHCP=op_DHCP[1:]
                    #on ajoute le padding
                    if(len(op_DHCP)!=0):#sachant que op_DHCP ne contient plus que des 0 car toutes les options ont été enlevées
                        padd="".join(str(oct) for oct in op_DHCP)
                        if len(padd)>40:
                            res_DHCP.append("    Padding: "+padd[0:40]+"...")
                        else:
                            res_DHCP.append("    Padding: "+padd)
                    analyse.append(res_DHCP)   
            #DNS
            elif (int(Dst_Port)==53 or int(Src_Port)==53):
                idx_dns=len(Ethernet)+len(IP)+8 
                DNS=frame[idx_dns:]
                identification="".join(str(oc) for oc in DNS[0:2])
                Flags="".join(str(oc) for oc in DNS[2:4])
                Flags_bin=tobin(int(Flags,16),16)
                Qr=Flags_bin[0] # Qr indique si c'est une requete(0) ou reponse(1)
                if int(Qr,2)==0:
                    Qr_str="request"
                else:
                    Qr_str="response" 
                Opcode=Flags_bin[1:5] #Opcode permet de specifier le type de requete
                if(int(Opcode,2)==0):
                    type_req="Standard Query"
                elif(int(Opcode,2)==1):
                    type_req="Iquery"
                elif(int(Opcode,2)==2):
                    type_req="Status"
                elif(int(Opcode,2)>=3 and int(Opcode,2)<=15):
                    type_req="Reserved"
                else:
                    type_req=""
                Aa=Flags_bin[5] #Il indique une reponse d'une entité autoritaire
                Tc=Flags_bin[6] #indique que ce message a été tronqué
                Rd=Flags_bin[7] #permet de demander la récursivité en le mettant à 1
                Ra=Flags_bin[8] #indique que la recursivité est autorisé
                Z=Flags_bin[9] #reservé pour une utilisation futur
                AA=Flags_bin[10] #Authentified Answer
                NAD=Flags_bin[11] #Non-Authenticated data
                Rcode=Flags_bin[12:] #indique le type de la reponse 
                if(int(Rcode,2)==0):
                    type_reponse="No error"
                elif(int(Rcode,2)==1):
                    type_reponse="Error" #!!!!!à verifier!!!!
                elif(int(Rcode,2)==2):
                    type_reponse="Server Problem"
                elif(int(Rcode,2)==3):
                    type_reponse="Not existant name"
                elif(int(Rcode,2)==4):
                    type_reponse="Not implemented" 
                elif(int(Rcode,2)==5):
                    type_reponse="Refused" 
                elif(int(Rcode,2)>=6 and int(Rcode,2)<=15):
                    type_reponse="Reserved"
                nb_Questions=int("".join(str(oc) for oc in DNS[4:6]),16)
                nb_Answers=int("".join(str(oc) for oc in DNS[6:8]),16)
                nb_Authority=int("".join(str(oc) for oc in DNS[8:10]),16)
                nb_Additional=int("".join(str(oc) for oc in DNS[10:12]),16)
                res_DNS.append("Domain Name System ("+Qr_str+")")
                res_DNS.append("    Transaction ID: 0x"+identification)
                res_DNS.append("    Flags: 0x"+Flags+" "+type_req+" "+Qr_str+", "+type_reponse)
                res_DNS.append("        ... .... .... .... = Response: Message is a "+Qr_str)
                res_DNS.append("        ."+Opcode+"... .... .... = Opcode: "+type_req+" ("+str(int(Opcode,2))+")")
                res_DNS.append("        .... ."+Aa+".. .... .... = Authoritative: "+("Server is not an authority for domain" if Aa=="0" else "Server is an authority for domain"))
                res_DNS.append("        .... .."+Tc+". .... .... = Truncated: Message is "+("not truncated" if Tc=="0" else "truncated"))
                res_DNS.append("        .... ..."+Rd+" .... .... = Recursion desired: "+("Do query recursively" if Rd=="1" else "A CHERCHER!!!!!!!"))
                res_DNS.append("        .... ...."+Ra+"... .... = Recursion available: Server can "+("do recursive queries" if Ra=="A" else "not do recursive queries"))
                res_DNS.append("        .... .... ."+Z+".. .... = Z: reserved ("+Z+")")
                res_DNS.append("        .... .... .."+AA+". .... = Answer authenticated: Answer/authority portion was "+("not authenticated by the server" if AA=="0" else "authenticated by the server"))
                res_DNS.append("        .... .... ..."+NAD+" .... = Non-authenticated data: "+("Unacceptable" if NAD=="0" else "Acceptable"))
                res_DNS.append("        .... .... .... "+Rcode+" = Reply code: "+type_reponse+" ("+str(int(Rcode,2))+")")
                res_DNS.append("    Questions: "+str(nb_Questions))
                res_DNS.append("    Answer RRs: "+str(nb_Answers))
                res_DNS.append("    Authority RRs: "+str(nb_Authority))
                res_DNS.append("    Additional RRs: "+str(nb_Additional))
                Sections=DNS[12:]
                #Questions 
                if(nb_Questions!=0):
                    res_DNS.append("    Queries")
                    for i in range(nb_Questions): 
                        idx_fin_name=get_index_fin_name(0,Sections)
                        Name=get_value_from_position_ch("",0,Sections,DNS)   
                        lab_count=Name.count('.')+1
                        typ="".join(oc for oc in Sections[idx_fin_name+1:idx_fin_name+3])
                        if(typ=="0001"):
                            typ_nom="A"
                            typ_meaning=" (Host Adress) "
                        elif(typ=="001c" or typ=="001C"):
                            typ_nom="AAAA"
                            typ_meaning=" (IPv6 Adress) "
                        elif(typ=="0005"):
                            typ_nom="CNAME"
                            typ_meaning=" (Canonical NAME for an alias) "
                        elif(typ=="0002"):
                            typ_nom="NS"
                            typ_meaning=" (Authorative Server Name) "
                        elif(typ=="000f" or typ=="000F"):
                            typ_nom="MX"
                            typ_meaning=" (Mail eXchange) "
                        else:
                            typ_nom="Uknown type (Not treated)"
                            typ_meaning=""
                        Class="".join(oc for oc in Sections[idx_fin_name+3:idx_fin_name+5])
                        if(typ=="0001" or typ=="001c" or typ=="001C" or typ=="0005" or typ=="000f" or typ=="000F"):
                            res_DNS.append("        "+Name+": type "+typ_nom+", class "+("IN" if Class=="0001" else "uknown class"))
                            res_DNS.append("            Name: "+Name)
                            res_DNS.append("            [Name Length: "+str(len(Name))+"]")
                            res_DNS.append("            [Label Count: "+str(lab_count)+"]")
                            res_DNS.append("            Type: "+typ_nom+typ_meaning+" ("+str(int(typ,16))+")")
                            res_DNS.append("            Class: "+("IN" if Class=="0001" else "uknown class")+" (0x"+Class+")")
                        else:
                            res_DNS.append("        Uknown type (Not treated)")
                        Sections=Sections[idx_fin_name+5:]
                    
                #Reponses  
                if(nb_Answers!=0):      
                    res_DNS.append("    Answers")   
                    for i in range(nb_Answers):
                        idx_fin_name=get_index_fin_name(0,Sections)
                        Name=get_value_from_position_ch("",0,Sections,DNS)
                        typ="".join(oc for oc in Sections[idx_fin_name+1:idx_fin_name+3])
                        if(typ=="0001"):
                            typ_nom="A"
                            typ_meaning=" (Host Adress) "
                        elif(typ=="001c" or typ=="001C"):
                            typ_nom="AAAA"
                            typ_meaning=" (IPv6 Adress) "
                        elif(typ=="0005"):
                            typ_nom="CNAME"
                            typ_meaning=" (Canonical NAME for an alias) "
                        elif(typ=="000f" or typ=="000F"):
                            typ_nom="MX"
                            typ_meaning=" (Mail eXchange) "
                        else:
                            typ_nom="Uknown type"
                            typ_meaning=""    
                        Class="".join(oc for oc in Sections[idx_fin_name+3:idx_fin_name+5])    
                        TTL=int(("".join(oc for oc in Sections[idx_fin_name+5:idx_fin_name+9])),16)
                        
                        Data_length=int(("".join(oc for oc in Sections[idx_fin_name+9:idx_fin_name+11])),16)
                        if typ=="000f" or typ=="000F":
                            Preference=int(("".join(oc for oc in Sections[idx_fin_name+11:idx_fin_name+13])),16)
                            data_hex=Sections[idx_fin_name+13:idx_fin_name+13+Data_length]
                        else:
                            data_hex=Sections[idx_fin_name+11:idx_fin_name+11+Data_length]
                        if(typ=="0001" or typ=="001C" or typ=="001c"):    
                            data=".".join(str(int(oc,16)) for oc in data_hex)
                        elif(typ=="0005" or typ=="000f" or typ=="000F"):
                            data=get_value_from_position_ch("",0,data_hex,DNS)
                        elif(typ=="0002"):
                            typ_nom="NS"   
                            typ_meaning=" (authorative Name Server) "   

                        if(typ=="0001" or typ=="001c" or typ=="001C" or typ=="0005" or typ=="000f" or typ=="000F"):
                            res_DNS.append("        "+str(Name)+": type "+typ_nom+", class "+("IN" if Class=="0001" else "")+", "+("addr" if (typ_nom=="A" or typ_nom=="AAAA") else ("mx" if typ_nom=="MX" else typ_nom))+" "+data)
                            res_DNS.append("            Name: "+Name)
                            res_DNS.append("            Type: "+typ_nom+typ_meaning+" ("+str(int(typ,16))+")")
                            res_DNS.append("            Class: "+("IN" if Class=="0001" else "")+" (0x"+Class+")")
                            res_DNS.append("            Time to live: "+str(TTL)+" ("+time_format(TTL)+")")
                            res_DNS.append("            Data length: "+str(Data_length))
                            if typ=="000f" or typ=="000F":
                                res_DNS.append("            Preference: "+str(Preference))
                            res_DNS.append("            "+("Address" if (typ_nom=="A" or typ_nom=="AAAA") else ("Mail Exchange" if typ_nom=="MX" else typ_nom))+": "+data)
                        elif(typ=="0002"):   #NS
                            i=0
                            n_s=[]                           
                            while(tobin(int(data_hex[i],16),8)[0:2]!='11' and data_hex[i]!='00'):
                                n_s.append(data_hex[i])
                                i+=1
                            if tobin(int(data_hex[i],16),8)[0:2]=='11':
                                n_s.append(data_hex[i])
                                n_s.append(data_hex[i+1])
                                data_hex=data_hex[i+2:]
                            else:
                                n_s.append(data_hex[i])
                                data_hex=data_hex[i+1:]      
                            name_server=get_value_from_position_ch("",0,n_s,DNS)     
                            res_DNS.append("        "+str(Name)+": type "+typ_nom+", class "+("IN" if Class=="0001" else "")+", ns "+name_server)
                            res_DNS.append("            Name: "+Name)
                            res_DNS.append("            Type: "+typ_nom+typ_meaning+" ("+str(int(typ,16))+")")
                            res_DNS.append("            Class: "+("IN" if Class=="0001" else "")+" (0x"+Class+")")
                            res_DNS.append("            Time to live: "+str(TTL)+" ("+time_format(TTL)+")")
                            res_DNS.append("            Data length: "+str(Data_length))
                            res_DNS.append("            name server: "+name_server)
                        else:
                            res_DNS.append("        Uknown type (Not treated)")
                        Sections=Sections[idx_fin_name+11+Data_length:]  
                #Authority
                if(nb_Authority!=0):
                    res_DNS.append("    Authoritative nameservers")                     
                    for i in range(nb_Authority):
                        idx_fin_name=get_index_fin_name(0,Sections)
                        Name=get_value_from_position_ch("",0,Sections,DNS)
                        typ="".join(oc for oc in Sections[idx_fin_name+1:idx_fin_name+3])
                        if(typ=="0006"):
                            typ_nom="SOA"  
                            typ_meaning=" (Start Of a zone of Authority) "   
                        elif(typ=="0002"):
                            typ_nom="NS"   
                            typ_meaning=" (authorative Name Server) "         
                        else:
                            typ_nom="Uknow type"           
                        Class="".join(oc for oc in Sections[idx_fin_name+3:idx_fin_name+5])  
                        TTL=int(("".join(oc for oc in Sections[idx_fin_name+5:idx_fin_name+9])),16)                       
                        Data_length=int(("".join(oc for oc in Sections[idx_fin_name+9:idx_fin_name+11])),16)
                        data_hex=Sections[idx_fin_name+11:idx_fin_name+11+Data_length]
                        if(typ=="0006"):    #SOA
                            i=0
                            P_n_s=[]                           
                            while(tobin(int(data_hex[i],16),8)[0:2]!='11' and data_hex[i]!='00'):
                                P_n_s.append(data_hex[i])
                                i+=1
                            if tobin(int(data_hex[i],16),8)[0:2]=='11':
                                P_n_s.append(data_hex[i])
                                P_n_s.append(data_hex[i+1])
                                data_hex=data_hex[i+2:]
                            else:
                                P_n_s.append(data_hex[i])
                                data_hex=data_hex[i+1:]      
                            Primary_name_server=get_value_from_position_ch("",0,P_n_s,DNS)   
                            
                            i=0
                            Resp_auth=[]
                            while(tobin(int(data_hex[i],16),8)[0:2]!='11' and data_hex[i]!='00'):
                                Resp_auth.append(data_hex[i])
                                i+=1
                            if tobin(int(data_hex[i],16),8)[0:2]=='11':
                                Resp_auth.append(data_hex[i])
                                Resp_auth.append(data_hex[i+1])
                                data_hex=data_hex[i+2:]
                            else:
                                Resp_auth.append(data_hex[i])
                                data_hex=data_hex[i+1:]   
                            Responsable_authority=get_value_from_position_ch("",0,Resp_auth,DNS)   
                            Serial=int(("".join(oct for oct in data_hex[0:4])),16)
                            Refresh_interval=int(("".join(oct for oct in data_hex[4:8])),16)
                            Retry_interval=int(("".join(oct for oct in data_hex[8:12])),16)
                            Expire_limit=int(("".join(oct for oct in data_hex[12:16])),16)
                            Minimum_TTL=int(("".join(oct for oct in data_hex[16:20])),16)    
                            res_DNS.append("        "+str(Name)+": type "+typ_nom+", class "+("IN" if Class=="0001" else "")+", mname "+Primary_name_server)
                            res_DNS.append("            Name: "+Name)
                            res_DNS.append("            Type: "+typ_nom+typ_meaning+" ("+str(int(typ,16))+")")
                            res_DNS.append("            Class: "+("IN" if Class=="0001" else "")+" (0x"+Class+")")
                            res_DNS.append("            Time to live: "+str(TTL)+" ("+time_format(TTL)+")")
                            res_DNS.append("            Data length: "+str(Data_length))
                            res_DNS.append("            Primary name server: "+Primary_name_server)
                            res_DNS.append("            Responsable authority's mailbox: "+Responsable_authority)
                            res_DNS.append("            Serial Number: "+str(Serial))
                            res_DNS.append("            Refresh Interval: "+str(Refresh_interval)+" ("+time_format(Refresh_interval)+")")
                            res_DNS.append("            Retry Interval: "+str(Retry_interval)+" ("+time_format(Retry_interval)+")")
                            res_DNS.append("            Expire limit: "+str(Expire_limit)+" ("+time_format(Expire_limit)+")")
                            res_DNS.append("            Minimum TTL: "+str(Minimum_TTL)+" ("+time_format(Minimum_TTL)+")")
                        elif(typ=="0002"):   #NS
                            i=0
                            n_s=[]                           
                            while(tobin(int(data_hex[i],16),8)[0:2]!='11' and data_hex[i]!='00'):
                                n_s.append(data_hex[i])
                                i+=1
                            if tobin(int(data_hex[i],16),8)[0:2]=='11':
                                n_s.append(data_hex[i])
                                n_s.append(data_hex[i+1])
                                data_hex=data_hex[i+2:]
                            else:
                                n_s.append(data_hex[i])
                                data_hex=data_hex[i+1:]      
                            name_server=get_value_from_position_ch("",0,n_s,DNS)     
                            res_DNS.append("        "+str(Name)+": type "+typ_nom+", class "+("IN" if Class=="0001" else "")+", ns "+name_server)
                            res_DNS.append("            Name: "+Name)
                            res_DNS.append("            Type: "+typ_nom+typ_meaning+" ("+str(int(typ,16))+")")
                            res_DNS.append("            Class: "+("IN" if Class=="0001" else "")+" (0x"+Class+")")
                            res_DNS.append("            Time to live: "+str(TTL)+" ("+time_format(TTL)+")")
                            res_DNS.append("            Data length: "+str(Data_length))
                            res_DNS.append("            name server: "+name_server)
                        else:
                            res_DNS.append("        Uknown type (Not treated in Authority)")

                        Sections=Sections[idx_fin_name+11+Data_length:]  
                #Additional       
                if(nb_Additional!=0):
                    res_DNS.append("    Additional records")
                    for i in range(nb_Additional):
                        idx_fin_name=get_index_fin_name(0,Sections)
                        Name=get_value_from_position_ch("",0,Sections,DNS)
                        typ="".join(oc for oc in Sections[idx_fin_name+1:idx_fin_name+3])
                        if(typ=="0001"):
                            typ_nom="A"
                            typ_meaning=" (Host Adress) "
                        elif(typ=="001c" or typ=="001C"):
                            typ_nom="AAAA"
                            typ_meaning=" (IPv6 Adress) "
                        else:
                            typ_nom="Uknown type"             
   
                        Class="".join(oc for oc in Sections[idx_fin_name+3:idx_fin_name+5])  
                        TTL=int(("".join(oc for oc in Sections[idx_fin_name+5:idx_fin_name+9])),16)                       
                        Data_length=int(("".join(oc for oc in Sections[idx_fin_name+9:idx_fin_name+11])),16)
                        data_hex=Sections[idx_fin_name+11:idx_fin_name+11+Data_length]
                        data=""
                        if(typ=="0001"):
                           data=".".join(str(int(oc,16)) for oc in data_hex)
                        elif(typ=="001c" or typ=="001C"):
                            data_hex_prime=[]
                            k=0
                            while(k<len(data_hex)):
                                data_hex_prime.append("".join(oc for oc in data_hex[k:k+2]))
                                k+=2
                            data=":".join(oc for oc in data_hex_prime)
                        else:
                            data=""
                        if(typ=="0001" or typ=="001c" or typ=="001C"):
                            res_DNS.append("        "+str(Name)+": type "+typ_nom+", class "+("IN" if Class=="0001" else "")+", "+("addr" if (typ_nom=="A" or typ_nom=="AAAA") else typ_nom)+" "+data)
                            res_DNS.append("            Name: "+Name)
                            res_DNS.append("            Type: "+typ_nom+typ_meaning+" ("+str(int(typ,16))+")")
                            res_DNS.append("            Class: "+("IN" if Class=="0001" else "")+" (0x"+Class+")")
                            res_DNS.append("            Time to live: "+str(TTL)+" ("+time_format(TTL)+")")
                            res_DNS.append("            Data length: "+str(Data_length))
                            res_DNS.append("            "+("Address" if (typ_nom=="A" or typ_nom=="AAAA") else typ_nom)+": "+data)
                        else:
                            res_DNS.append("        Uknown type (Not treated in Additional)")
                        Sections=Sections[idx_fin_name+11+Data_length:]  
                analyse.append(res_DNS)
            else:
                analyse.append(["Unknown Protocol"," "])
        
        else:
                analyse.append([name_protocol+ " (Not treated)"," "])
            
    elif (Type=='0806'):
        analyse.append(["Address Resolution Protocol (ARP) (not treated)"," "]) 
    else:
        analyse.append(["Unknown Protocol"," "])
    return analyse

def time_format(TTL):
    TTL_format=""
    if TTL <60 :
        TTL_format=str(TTL)+" seconds" 
    elif TTL>=60 and TTL<3600:
        TTL_format=str(TTL//60)+" minutes"
        if(TTL%60!=0):
            TTL_format+=" and "+str(TTL%60)+" seconds" 
    elif TTL>=3600 and TTL<86400:
            TTL_format=str(TTL//3600)+" hours"
            if(TTL%3600!=0):
                TTL_format+=" and "+str(TTL%3600)+" seconds" 
    elif TTL>=86400:
            TTL_format=str(TTL//86400)+" days"
    return TTL_format

def get_value_from_position_ch(value,position,liste,dns_list,nb=0):
   
    if tobin(int(liste[position],16),8)[0:2]=='11': #c'est une Compression labe si les 2 premiers bits sont 11      
        carac=list(tobin(int(liste[position],16),8))
        carac[0]="0"
        carac[1]="0"                               #(si on a c0 02-->la position=00 02)
        bina="".join(carac)
        liste[position]=hex(int(bina,2))[2:]
        value_location=int(("".join(oc for oc in liste[position:position+2])),16)
        return get_value_from_position_ch(value,value_location,dns_list,dns_list)
    else:
        value_start=liste[position:]
        j=1       
        while j<len(value_start) and value_start[j]!='00' and tobin(int(value_start[j],16),8)[0:2]!='11':                   
            if(int(value_start[j],16)<20):
                value+='.'
            else:       
                value+=bytes.fromhex(value_start[j]).decode("ASCII")
            j+=1   
        if(j<len(value_start)):
            if(tobin(int(value_start[j],16),8)[0:2]=='11'):
                carac=list(tobin(int(value_start[j],16),8))
                carac[0]="0"
                carac[1]="0"                               #(si on a c0 02-->la position=00 02)
                bina="".join(carac)
                value_start[j]=hex(int(bina,2))[2:]
                if value!="":
                    value+="."
                value_location=int(("".join(oc for oc in value_start[j:j+2])),16)
                return get_value_from_position_ch(value,value_location,dns_list,dns_list)
    return value 



def get_index_fin_name(position,liste):
    idx=0
    if tobin(int(liste[position],16),8)[0:2]=='11': #c'est une Compression labe si les 2 premiers bits sont 11
            idx+=1
    else:
        value_start=liste[position:]
        j=1    
        while j<len(value_start) and value_start[j]!='00' and tobin(int(value_start[j],16),8)[0:2]!='11':                   
            j+=1  
            idx+=1 
        if(j<len(value_start)):
            if(tobin(int(value_start[j],16),8)[0:2]=='11'):
                idx+=2
            else:
                idx+=1
    return idx


    return analyse

tobin = lambda x, count=8: "".join(map(lambda y:str((x>>y)&1),range(count-1,-1,-1)))    

def get_op_name(op_type):
    if op_type==7:
        return "Record Route"
    elif op_type==0:
        return "End of Options List (EOL)"
    elif op_type==1:
        return "No Operation"
    elif op_type==68:
        return "Time Stamp (TS)"
    elif op_type==131:
        return "Loose Routing"
    elif op_type==137:
        return "Strict Routing"
    elif op_type==1:
        return "No-Operation (NOP)"
    else: 
        return "Unkown Option"

def get_op_dhcp(op_t):
    if op_t==1:
        return "Subnet Mask"
    elif op_t==15:
        return "Domain Name"
    elif op_t==3:
        return "Router"
    elif op_t==81:
        return "Client Fully Qualified Domain Name"
    elif op_t==6:
        return "Domain Name Server"
    elif op_t==44:
        return "NetBIOS over TCP/IP Name Server"
    elif op_t==46:
        return "NetBIOS over TCP/IP Node Type"
    elif op_t==47:
        return "NetBIOS over TCP/IP Scope"
    elif op_t==31:
        return "Perform Router Discover"
    elif op_t==33:
        return "Static Route"
    elif op_t==249:
        return "Private/Classeless Static Route (Microsoft)"
    elif op_t==43:
        return "Vendor-Specific Information"
    elif op_t==57:
        return  "Maximum DHCP Message Size"
    else :
        return "Unknown option"

def taille_trame(list_list):
    """renvoie la taille d'une trame en octet"""
    taille=0
    for i in range(len(list_list)):
        taille+=len(list_list[i])-1
    return taille