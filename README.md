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
| Service Windows et accès pré-connexion | à faire |
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
