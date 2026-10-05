# sidgate

Accès distant à une station Windows, sans cloud tiers, sans port ouvert, et sans
consommer de CPU quand personne n'est connecté.

L'écran est capturé en VRAM, encodé par l'ASIC vidéo du GPU, et transporté en
WebRTC. Aucune image ne traverse la mémoire centrale ni le processeur.

```
[ client PWA ] ──WebRTC──► [ agent Rust ] ──DXGI──► [ GPU ]
       │                          │
       └──WireGuard────────────────┘
                  via [ Raspberry Pi ] : coordination du maillage + réveil WoL
```

Le client est une page web servie par l'agent lui-même : rien à installer sur le
téléphone, la tablette ou l'ordinateur d'où l'on se connecte.

## Ce que fait la version 1.0

| | |
| --- | --- |
| Vidéo | H.264 matériel (NVENC, AMF ou QuickSync via Media Foundation), jusqu'à 240 i/s, quatre paliers de qualité |
| Reprise sur perte | Retransmission, image clé à la demande, débit abaissé quand le lien perd des paquets |
| Écrans | Choix de l'écran depuis le client, suivi des changements de résolution |
| Curseur | Position et forme réelles du curseur de l'hôte, dessinées par le client |
| Souris | Pointage direct ou trackpad, molette haute résolution, boutons latéraux |
| Tactile | Toucher, appui long, deux doigts pour défiler ou cliquer droit, double toucher pour glisser |
| Clavier | Scancodes pour un clavier matériel, saisie de texte Unicode pour un clavier virtuel |
| Presse-papiers | Coller un texte local sur l'hôte ; copier celui de l'hôte, si l'hôte l'autorise |
| Système | Verrouillage, et sur autorisation : veille, redémarrage, extinction |
| Sessions | Une à la fois ; un appareil appairé qui se connecte reprend la session en cours |
| Service | Démarrage au boot, suivi du bureau d'entrée, journal sur disque |
| Nœud sentinelle | Headscale, Caddy, nftables et réveil Wake-on-LAN sur Raspberry Pi |

### Ce qu'elle ne fait pas

- **Windows uniquement.** L'agent ne se compile pas ailleurs ; un backend Linux
  (PipeWire, VA-API) n'existe pas.
- **Pas de son.** Seule l'image est transmise.
- **Pas de transfert de fichiers**, et le presse-papiers ne porte que du texte.
- **Pas de Ctrl+Alt+Suppr.** Windows réserve cette séquence au clavier physique
  et ignore celle qu'un programme injecte. Le gestionnaire des tâches s'ouvre
  par Ctrl+Maj+Échap, proposé dans le panneau.
- **Pas d'écran pivoté.** Windows livre son image dans l'orientation du
  panneau ; elle n'est pas redressée.

## Mesuré sur une machine réelle

Intel QuickSync, bureau 1920×1200, 12 cœurs logiques :

| | Mesure | Cible |
| --- | --- | --- |
| CPU en session | **1,5 %** | < 2 % |
| CPU au repos | **0,000 %** | 0,0 % |
| Mémoire, agent jamais connecté | **2,4 Mo** engagés | < 15 Mo |
| Encodage | **3,9 ms**/image | — |
| Débit de l'ASIC | **243 i/s** en 1920×1200 | ≥ 60 i/s |

La mémoire après une session retombe à ~138 Mo et non à 2,4 Mo : les DLL du
pilote GPU et de Media Foundation restent chargées une fois utilisées. Y
remédier demanderait d'isoler la capture dans un processus enfant détruit à la
fin de session.

Ces chiffres datent de la version 0.1. La charge CPU et la mémoire de l'agent
sont depuis mesurées en continu et affichées par le client, dans « Détails ».

### Latence

La cible de 35 ms **n'est pas démontrée**. Ce qui est mesuré, en boucle locale :

| Terme | Mesure |
| --- | --- |
| Capture et encodage | 2 à 4 ms |
| Réseau (moitié de l'aller-retour) | 0,5 ms |
| Tampon de gigue du navigateur, régime établi | ~22 ms |
| Décodage | 1 à 4 ms |
| **Somme** | **≥ 29 ms** |

C'est une borne basse : n'y figurent ni l'attente de présentation du
compositeur de l'hôte, ni la synchronisation verticale de l'écran client —
jusqu'à une image chacune à 60 Hz. Une mesure écran à écran reste à faire.

Le tampon de gigue dominait avant réglage. Le client fixe désormais
`jitterBufferTarget = 0` sur le récepteur vidéo. Sur une paire de sessions à
bureau actif : 61 à 281 ms par image sans réglage, 30 à 60 ms avec. Une seule
paire exploitable, sous une charge non contrôlée : l'écart est net, pas encore
chiffré avec rigueur.

La télémétrie du client affiche cette somme en direct, et `n/d` pour tout terme
que le navigateur n'expose pas plutôt qu'un zéro inventé.

## Démarrage

Il faut Rust 1.82 ou plus récent, et un GPU doté d'un encodeur H.264 matériel.

```bash
cargo build --release
./target/release/sidgate.exe run
```

L'agent affiche un code d'appairage et sert le client sur
`https://127.0.0.1:8443`. Ouvrir cette adresse, accepter le certificat
auto-signé, saisir le code. Le client garde ensuite sa clé : le code ne sert
qu'une fois.

Dans la console de l'agent, `p` puis Entrée rouvre un appairage, `x` l'annule,
`c` liste les appareils autorisés.

### Commandes

| | |
| --- | --- |
| `sidgate run [--pair]` | Démarre l'agent dans la console |
| `sidgate pair` | Ouvre un appairage sur l'agent en cours d'exécution et affiche le code |
| `sidgate clients` | Liste les appareils appairés |
| `sidgate revoke <clé>` | Révoque un appareil ; sa session en cours se ferme sous cinq secondes |
| `sidgate info` | Identité, adresse d'écoute, permissions, état du répertoire de données |
| `sidgate protect` | Ferme le répertoire de données aux autres comptes de la machine |
| `sidgate service install\|uninstall\|start\|stop\|status` | Pilote le service Windows |

`pair`, `clients` et `revoke` agissent sur un agent en marche sans lui parler :
ils écrivent dans le répertoire de données, que l'agent relit à la connexion
suivante. Aucun canal local n'est à l'écoute.

### Utiliser le client

Le panneau de commandes se déplie depuis le bas de l'écran.

| Geste | Effet |
| --- | --- |
| Souris, mode **pointage direct** | Le pointeur de l'hôte suit le vôtre |
| Souris, mode **trackpad** | Un clic capture la souris, Échap la libère |
| Un doigt | Déplace le pointeur ; un toucher bref clique |
| Double toucher, le second maintenu | Fait glisser |
| Appui long, ou toucher à deux doigts | Clic droit |
| Deux doigts qui glissent | Défilement |

« Clavier » ouvre le clavier virtuel de l'appareil. Ctrl, Alt et Maj sont des
bascules : appuyées, elles s'appliquent à la frappe suivante. « Coller » tape sur
l'hôte le texte du presse-papiers local.

En plein écran, Chrome et Edge cèdent au client les touches qu'ils gardent
d'ordinaire pour eux : Échap, Alt+Tab, la touche Windows.

## Configuration

`%PROGRAMDATA%\sidgate\sidgate.toml`, écrit au premier lancement. Tout y est
refusé par défaut :

```toml
[network]
bind = "127.0.0.1"          # adresse d'écoute ; en production, celle de WireGuard
port = 8443
tls = true                  # ne se désactive que sur la boucle locale
stun_servers = []           # vide : aucun serveur tiers n'est contacté

[video]
output = 0                  # écran capturé à l'ouverture d'une session
framerate = 60              # cadence maximale, de 1 à 240
quality = "balanced"        # low, balanced, high ou ultra
adaptive_bitrate = true     # baisser le débit quand le client perd des paquets

[security]
allow_power_actions = false # veille, redémarrage, extinction
allow_input = true          # souris et clavier ; false donne une session en lecture seule
allow_clipboard = false     # lecture du presse-papiers de l'hôte par le client
lock_on_disconnect = true   # verrouiller la session Windows à la fin
pairing_window_secs = 120
auth_attempts_per_minute = 10
```

Une clé inconnue fait échouer le chargement : une faute de frappe ne laisse pas
tourner un agent avec un réglage qu'on croyait avoir changé.

| Variable | |
| --- | --- |
| `SIDGATE_DATA_DIR` | Répertoire de données, à la place de `%PROGRAMDATA%\sidgate` |
| `SIDGATE_LOG` | Filtre de journalisation, par exemple `sidgate=debug` |
| `SIDGATE_WORKER_IDENTITY` | `system` pour l'accès pré-connexion, voir plus bas |

En production, mettre `bind` à l'adresse de l'interface WireGuard : l'agent
n'existe alors sur aucune interface physique.

## Service Windows

Pour que l'agent démarre au boot et survive aux changements de session, depuis
une invite **administrateur** :

```bash
sidgate service install
sidgate service start
```

Puis, pour appairer un premier appareil :

```bash
sidgate pair
```

Depuis une invite ordinaire dans le cas général ; élevée si le travailleur
tourne en SYSTEM, puisque le répertoire de données appartient alors au système.

`sidgate service status` renseigne sur l'état, sans élévation. Le journal du
travailleur est dans `%PROGRAMDATA%\sidgate\sidgate.log`.

Le service ne fait qu'une chose : maintenir un travailleur vivant dans la
session interactive, et le relancer quand elle change. Il n'ouvre aucun socket
et ne lit rien venant du réseau — c'est le seul processus tournant en
permanence sous le compte système, et sa pauvreté est délibérée.

### Accès pré-connexion

Par défaut le travailleur prend l'identité de l'utilisateur connecté : moindre
privilège, mais il ne peut pas capturer l'écran de verrouillage : ce bureau
appartient à Winlogon et son descripteur de sécurité l'en exclut. Le client
reste alors connecté, le dit, et la vidéo reprend au déverrouillage.

Pour un écran verrouillé, il faut que le travailleur tourne en SYSTEM dans la
session interactive :

```
SIDGATE_WORKER_IDENTITY=system
```

C'est un vrai compromis : le processus qui écoute le réseau devient SYSTEM.
Il se réclame explicitement, et n'arrive jamais par effet de bord.

## Sécurité

- **Aucun port applicatif exposé.** Seul WireGuard écoute sur l'Internet public,
  et il ignore silencieusement tout paquet non signé.
- **Authentification mutuelle**, indépendante du VPN et du TLS : le client signe
  en ECDSA P-256, l'agent en Ed25519, sur une transcription commune qui inclut
  les deux aléas. Une signature capturée ne rejoue pas. La clé privée du client
  est non extractible : même du code exécuté dans la page ne peut pas la lire.
- **Appairage par code à usage unique**, ouvert depuis l'hôte lui-même — sa
  console ou `sidgate pair` — jamais depuis le réseau.
- **Répertoire de données fermé.** La clé de l'agent, le registre des clients et
  les demandes d'appairage ne sont accessibles qu'au système, aux
  administrateurs et au compte qui a créé le répertoire. Sans cela, n'importe
  quel compte du poste pourrait s'appairer.
- **Aucun interpréteur de commandes joignable.** Les commandes distantes sont une
  énumération fermée sans champ texte libre ; un test balaie les sources et
  échoue si un moyen d'exécuter un processus y apparaît.
- **Killswitch** : la session Windows se verrouille dès que le transport tombe
  ou que le client part. Seule exception, la reprise par un autre appareil
  appairé, qui ne l'interrompt pas.
- **Rien avant l'authentification.** Un visiteur non authentifié n'approche pas
  de la session en cours, et les poignées de main en attente sont plafonnées.
- **Révocation immédiate** : `sidgate revoke` ferme la session du client visé.
- **Biométrie facultative** côté client : Face ID, empreinte ou Windows Hello
  avant chaque connexion, à activer depuis l'écran d'accueil.

Le presse-papiers de l'hôte est le seul texte qui sorte de la machine sur
demande du client. Il est refusé par défaut : on y trouve volontiers un mot de
passe copié une minute plus tôt.

## Nœud sentinelle

Le Raspberry Pi coordonne le maillage WireGuard et réveille la station par
Wake-on-LAN. Il ne voit jamais le contenu d'une session. Voir
[infra/pi/README.md](infra/pi/README.md).

## Développement

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
node --test "client/tests/*.test.mjs"
```

Pour essayer une session sans toucher à l'installation réelle ni verrouiller
son propre poste à chaque déconnexion, donner à l'agent un répertoire à part :

```bash
SIDGATE_DATA_DIR=./essai ./target/release/sidgate.exe run
```

puis, dans `./essai/sidgate.toml`, `tls = false` (servi sur
`http://localhost:8443`, sans certificat à accepter) et
`lock_on_disconnect = false`.

Le client est embarqué dans le binaire à la compilation : une modification de
`client/` demande de recompiler l'agent.

### Structure

```
crates/sidgate-proto      protocole partagé, sans dépendance système
crates/sidgate-capture    capture DXGI, forme du curseur
crates/sidgate-encode     encodage Media Foundation
crates/sidgate-input      injection d'entrées, actions système, presse-papiers
crates/sidgate-agent      binaire : signalisation, WebRTC, dispatcher, service
client/                   PWA ; core.js porte la logique testée hors navigateur
infra/pi/                 nœud sentinelle
```

Les changements d'une version à l'autre sont dans [CHANGELOG.md](CHANGELOG.md).

## Licence

AGPL-3.0-only.
