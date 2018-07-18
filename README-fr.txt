Fonctionnement interne de la diode CLIP
=======================================

Du point de vue de l'extérieur la diode clip existe via deux sockets : /var/run/cryptd-red et /var/run/cryptd-black.

Les programmes présents dans rmb se connectent et échangent avec /var/run/cryptd-black.
Les programmes présents dans rmh se connectent et échangent avec /var/run/cryptd-red.

Du point de vue des processus : deux s'exécutent :
- un processus "slave" qui écoute sur les deux sockets précédentes
- un processus "master" qui crée le "slave" et communique avec lui via une paire de sockets

Le processus master est lancé et arrêté par les commandes qu'on trouve dans :
portage-overlay-clip/app-crypt/cryptd-server/files : cryptd.start et cryptd.stop.

Le démarrage se fait par la commande :
start-stop-daemon --start -x cryptd -- -r /var/run/cryptd-red -b /var/run/cryptd-black -f cd -c /usr/bin/crypt_getpass.sh -F -v

N.B.
====

crypt_getpass.sh : est un script qui entre dans la cage user et affiche différentes boites de dialgues de confirmation ou saisie de code pin, mot de passe etc.


Dans le processus "slave" ces deux sockets sont créés par la fonction server.c:static int slave_server_loop(void) et toujours dans ce processus :
- le ciphertext_server.c écoute sur la socket noire.
- le cleartext_server.c écoute sur la socket rouge.

Quand on souhaite faire passer un fichier d'une socket à l'autre, le ciphertext/cleartext_server.c fait passer en éventuellement chiffrant/déchiffrant le fichier via diode.c (diode montante) ou crypt.c (diode chiffrante) à l'autre cleartext/ciphertext_server.c. Mais avant de faire le transfert, il envoie une demande de confirmation au master sous forme d'une "commande externe".

====================================================================================================================

Communication entre le serveur slave et le serveur master :
-----------------------------------------------------------
=> pour envoyer une commande au serveur master le serveur slave utilise la fonction :
   extcmd.c:run_ext_cmd(extcmd_arg_t *arg)

qui est par exemple appelé par :
   diode.c:static inline uint32_t confirm(char *name, uint32_t len, uint32_t uid) qui appelle extcmd.c:run_ext_cmd(extcmd_arg_t *arg)

Dans le processus master :
--------------------------
la fonction extcmd.c:handle_extcmd récupère sur la socket qu'elle reçoit en argument la commande avec laquelle elle peuple les variables d'environnement dans lequel elle exécute crypt_getpass.sh.

Dans la pratique :
extcmd.c:handle_extcmd appelle extcmd.c:do_run_ext_cmd qui appelle run_cmd qui fait un execve sur la variable extcmd.c:g_ext_cmd qui a été initialisée avec le paramètre "-c" de l'exécutable cryptd, avec la ligne de commande précédente : crypt_getpass.sh.

sachant que extcmd_handler appelée par le master à la fin de son initialisation fonctionne en écoutant la socket stockée par le master dans g_extcmd_sock.

Attention car dans le processus master : il y a fork d'un nouveau processus pour exécuter "crypt_getpass.sh" dans la fonction extcmd.c:do_run_ext_cmd
