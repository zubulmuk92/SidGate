# Journal des modifications

Les versions suivent le [versionnage sémantique](https://semver.org/lang/fr/).
Le protocole entre l'agent et son client a son propre numéro : le client est
servi par l'agent, les deux changent donc toujours ensemble.

## 1.0.0

Protocole 2. Un client resté sur une page de la version précédente est refusé à
la poignée de main et invité à recharger.

### Corrigé

- **Une perte de paquet abîmait l'image jusqu'à la fin de la session.** Le flux
  n'a pas d'images clés périodiques, et rien ne les redemandait. Les demandes de
  retransmission, d'image clé et les rapports de réception du navigateur sont
  maintenant honorés.
- **Un clic tombait au mauvais endroit sur un poste à plusieurs écrans.** Les
  positions absolues portaient sur l'ensemble des écrans au lieu de l'écran
  capturé.
- **Le curseur affiché dérivait du curseur réel.** Le client l'estimait à partir
  de ses propres gestes, sans connaître l'accélération du pointeur de l'hôte. Il
  affiche désormais la position que l'hôte lui transmet.
- **Une touche pouvait rester enfoncée sur l'hôte.** Les relâchements voyageaient
  sur le canal sans retransmission ; ils empruntent le canal fiable.
- **Le clavier virtuel d'un téléphone ne tapait rien.** Il ne produit pas de
  touches mais du texte, que le protocole ne savait pas transporter.
- **« Ctrl+W » envoyait Ctrl+Z à un hôte AZERTY.** Les raccourcis du panneau
  désignaient les lettres par position ; ils les désignent par caractère, et
  l'hôte retrouve la touche sur sa propre disposition.
- **La fin d'un geste rapide n'était pas affichée.** L'image en avance sur la
  cadence était écartée, et si rien d'autre ne bougeait ensuite, le client
  restait sur l'image d'avant.
- **Une image isolée arrivait avec un dixième de seconde de retard.** Une fois
  soumise à l'encodeur, sa sortie n'était relevée qu'à l'image suivante du
  bureau : sur un écran par ailleurs immobile, l'écho d'une frappe attendait.
- **Deux boutons de souris pressés ensemble en laissaient un enfoncé.** Le
  navigateur ne signale que le premier appui et le dernier relâchement ; les
  boutons se lisent maintenant dans le masque de chaque événement.
- **Une erreur de négociation laissait la capture tourner**, sans verrouiller le
  poste : la fermeture de session passe par un chemin unique.
- **Une révocation n'atteignait pas un agent en marche** avant son redémarrage.
- **La télémétrie annonçait 0 % de CPU et 0 Mo**, écrits en dur. Les deux sont
  mesurés, ou absents.
- **Le premier message de l'agent pouvait se perdre** quand le pipeline démarrait
  avant l'ouverture du canal de contrôle.
- **Le défilement s'emballait au pavé tactile.** Chaque événement
  de molette valait un cran entier.
- Le bouton « Ctrl+Alt+Suppr » est retiré : Windows ignore cette séquence quand
  elle est injectée. « Gest. tâches » le remplace.
- `sidgate info` annonçait `https` même quand l'agent servait en clair.

### Ajouté

- Choix de l'écran capturé depuis le client, et suivi des changements de
  résolution.
- Forme réelle du curseur de l'hôte.
- Débit adapté aux pertes : le palier de qualité devient un plafond
  (`video.adaptive_bitrate`).
- Reprise de session : un appareil appairé qui se connecte remplace la session
  en cours, sans verrouiller le poste.
- `sidgate pair` : appairage d'un agent en service, sans console.
- `sidgate protect`, et fermeture du répertoire de données aux autres comptes
  de la machine dès sa création.
- Lecture du presse-papiers de l'hôte, refusée par défaut
  (`security.allow_clipboard`), et collage d'un texte local sur l'hôte.
- Gestes tactiles : appui long, toucher et défilement à deux doigts, glisser par
  double toucher. Modificatrices à bascule.
- Reconnexion automatique après une coupure subie.
- Relance de la capture quand elle s'arrête d'elle-même — pilote graphique
  réinitialisé — et repli sur le premier écran si celui demandé a disparu.
- Suivi des écrans branchés, débranchés ou déplacés en cours de session.
- Un appareil révoqué peut oublier l'hôte et s'appairer de nouveau depuis
  l'écran d'accueil.
- Journal sur disque pour le travailleur lancé par le service.
- Icônes d'application, mise en page pour téléphone tenu debout, panneau de
  détails de la télémétrie.
- Intégration continue et construction des versions.

### Modifié

- La biométrie n'est plus proposée d'office après l'appairage : elle s'active
  depuis l'écran d'accueil.
- Le mode de pointage n'est plus une commande du protocole. L'agent la recevait
  sans s'en servir ; c'est une affaire purement cliente.
- Les candidats ICE en `.local` sont ignorés : les résoudre demandait une
  diffusion mDNS sur le réseau physique.
- Les journaux partent sur la sortie d'erreur, la sortie standard restant celle
  des commandes.
- Les tests du client se lancent par `node --test "client/tests/*.test.mjs"`.

## 0.1.0

Première version : capture DXGI, encodage matériel, transport WebRTC,
authentification mutuelle, appairage, injection d'entrées, client PWA, service
Windows, nœud sentinelle.
