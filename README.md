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

```bash
node client/tests/latency.test.mjs
```

## État

| Phase | |
| --- | --- |
| Protocole partagé, codec binaire des entrées | fait |
| Capture DXGI Desktop Duplication | fait |
| Encodage H.264 matériel (NVENC / AMF / QuickSync via Media Foundation) | fait |
| Signalisation, authentification mutuelle, appairage | fait |
| Transport WebRTC, machine à états, killswitch | fait |
| Injection d'entrées, dispatcher de commandes | fait |
| Client PWA | fait |
| Nœud Raspberry Pi : Headscale, Caddy, nftables, réveil WoL | fait |
| Service Windows, suivi du bureau d'entrée | fait |
| Backend Linux (PipeWire / VA-API) | à faire |

## Démarrage

```bash
cargo build --release
./target/release/sidgate.exe run
```

L'agent affiche un code d'appairage et sert la PWA sur `https://127.0.0.1:8443`.
Ouvrir cette adresse, accepter le certificat auto-signé, saisir le code.

Taper `p` puis Entrée dans la console pour rouvrir un appairage, `x` pour
l'annuler, `c` pour lister les appareils autorisés.

Configuration dans `%PROGRAMDATA%\sidgate\sidgate.toml`. Tout y est refusé par
défaut : écoute sur la boucle locale, actions d'alimentation désactivées.

## Service Windows

Pour que l'agent démarre au boot et survive aux changements de session, depuis
une invite **administrateur** :

```bash
sidgate service install
sidgate service start
```

`sidgate service status` renseigne sur l'état, sans élévation.

Le service ne fait qu'une chose : maintenir un travailleur vivant dans la
session interactive, et le relancer quand elle change. Il n'ouvre aucun socket
et ne lit rien venant du réseau — c'est le seul processus tournant en
permanence sous le compte système, et sa pauvreté est délibérée.

### Accès pré-connexion

Par défaut le travailleur prend l'identité de l'utilisateur connecté : moindre
privilège, mais il ne peut pas capturer l'écran de verrouillage : ce bureau
appartient à Winlogon et son descripteur de sécurité l'en exclut.

Pour un écran verrouillé, il faut que le travailleur tourne en SYSTEM dans la
session interactive :

```
SIDGATE_WORKER_IDENTITY=system
```

C'est un vrai compromis : le processus qui écoute le réseau devient SYSTEM.
Il se réclame explicitement, et n'arrive jamais par effet de bord.

En production, mettre `bind` à l'adresse de l'interface WireGuard : l'agent
n'existe alors sur aucune interface physique.

## Sécurité

- **Aucun port applicatif exposé.** Seul WireGuard écoute sur l'Internet public,
  et il ignore silencieusement tout paquet non signé.
- **Authentification mutuelle**, indépendante du VPN et du TLS : le client signe
  en ECDSA P-256, l'agent en Ed25519, sur une transcription commune qui inclut
  les deux aléas. Une signature capturée ne rejoue pas.
- **Appairage par code à usage unique**, ouvert depuis la console de l'hôte,
  jamais depuis le réseau.
- **Aucun interpréteur de commandes joignable.** Les commandes distantes sont une
  énumération fermée sans champ texte libre ; un test balaie les sources et
  échoue si un moyen d'exécuter un processus y apparaît.
- **Killswitch** : la session Windows se verrouille dès que le transport tombe.

## Structure

```
crates/sidgate-proto      protocole partagé, sans dépendance système
crates/sidgate-capture    capture DXGI
crates/sidgate-encode     encodage Media Foundation
crates/sidgate-input      injection d'entrées, actions système
crates/sidgate-agent      binaire : signalisation, WebRTC, dispatcher
client/                   PWA
infra/pi/                 nœud sentinelle
```

## Licence

AGPL-3.0-only.
