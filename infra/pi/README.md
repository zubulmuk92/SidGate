# Nœud sentinelle

Raspberry Pi allumé en permanence, en Ethernet. Il coordonne le maillage
WireGuard, termine le TLS public, et réveille la station de travail.

Il ne voit jamais le contenu d'une session : la vidéo et les entrées passent en
direct entre le client et l'agent.

## Déploiement

```bash
cp .env.example .env && $EDITOR .env
sed -i "s/SIDGATE_DOMAIN/$(grep SIDGATE_DOMAIN .env | cut -d= -f2)/" headscale/config.yaml
docker compose up -d
```

Créer ensuite un utilisateur et enrôler les appareils :

```bash
docker exec sidgate-headscale headscale users create alexis
docker exec sidgate-headscale headscale preauthkeys create --user alexis --expiration 1h
```

## Réveil à distance

```bash
cd wol && cargo build --release
sudo install -m 0755 target/release/sidgate-wol /usr/local/bin/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sidgate-wol
sudo install -d -m 0750 /etc/sidgate
sudo cp ../wol.toml.example /etc/sidgate/wol.toml && sudo $EDITOR /etc/sidgate/wol.toml
sudo chown -R sidgate-wol:sidgate-wol /etc/sidgate
sudo cp ../sidgate-wol.service /etc/systemd/system/
sudo systemctl enable --now sidgate-wol
```

Depuis un appareil du tunnel, ouvrir `http://100.64.0.1:9797/` : la page liste
les machines déclarées et envoie le Magic Packet d'un clic. Elle est servie par
le Pi et non par l'agent, puisque l'agent est éteint quand on en a besoin.

En ligne de commande :

```bash
curl -X POST -H "X-Sidgate-Token: $TOKEN" http://100.64.0.1:9797/wake/station
```

## Filtrage

```bash
sudo cp nftables.conf /etc/nftables.conf
sudo systemctl enable --now nftables
```

Adapter `LAN_IFACE`, `WG_IFACE` et `ADMIN_NET` avant d'appliquer, sous peine de
perdre l'accès SSH.

## Ce qui est exposé sur l'Internet public

| Port | Service | Pourquoi |
| --- | --- | --- |
| 51820/udp | WireGuard | Rejette silencieusement tout paquet non signé |
| 80, 443/tcp | Caddy → Headscale | Enrôlement des appareils et certificat |

Rien d'autre. Ni la signalisation, ni le flux vidéo, ni le service de réveil ne
sont joignables autrement que depuis le tunnel.
