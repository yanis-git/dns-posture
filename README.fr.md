# ovh-domain-manager

[English](README.md) · **Français**

[![CI](https://github.com/yanis-git/ovh-domain-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/yanis-git/ovh-domain-manager/actions/workflows/ci.yml)
[![Licence : MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2020.12-brightgreen.svg)](#pr%C3%A9requis)
[![Zéro dépendance](https://img.shields.io/badge/d%C3%A9pendances%20runtime-0-brightgreen.svg)](package.json)

Réduction de la surface d'attaque et durcissement DNS « fermé par défaut » pour un portefeuille de
noms de domaine OVHcloud. Cartographiez les domaines dormants, évaluez l'ensemble du portefeuille
contre un référentiel de contrôles rattaché aux RFC, à l'ISO/IEC 27001:2022, à NIS 2 et aux
recommandations de l'ANSSI, puis publiez les enregistrements qui empêchent quiconque d'envoyer du
courrier en votre nom.

Un domaine dormant est un passif. Il résout encore, il porte encore un MX, et sauf mention
explicite du contraire, n'importe qui peut forger un courriel avec un `From:` à votre nom — fausse
facture, réinitialisation de mot de passe, hameçonnage de vos clients — et le message passera les
contrôles de base. En DNS, l'absence n'est pas une porte fermée : sans enregistrement CAA,
**toute** autorité de certification du monde peut émettre un certificat pour le domaine ; sans MX
nul, sa posture vis-à-vis du courrier entrant reste ambiguë. Cet outil recense ces domaines, mesure
ce qu'ils autorisent encore par omission, et publie les enregistrements qui ferment la porte.

Zéro dépendance à l'exécution. Tout fonctionne en simulation par défaut, et chaque modification est
précédée d'une sauvegarde complète de la zone.

| | |
|---|---|
| **Anti-usurpation d'identité** | SPF `-all`, DMARC `p=reject` en alignement strict, révocation DKIM par joker. |
| **Fermé par défaut** | MX nul (RFC 7505) et interdiction CAA optionnelle (RFC 8659) : rien n'est permis par omission. |
| **Surface d'attaque** | Jokers DNS, sous-domaines de service résiduels, TXT de vérification périmés, CNAME orphelins. |
| **Preuve d'audit** | Un audit du portefeuille complet, scoré, reproductible et hors ligne, en markdown, JSON et CSV. |

> **La sortie de l'outil, son aide en ligne et ses commentaires de code sont en anglais.** Cette
> page et [docs/CONFORMITE.md](docs/CONFORMITE.md) sont la documentation francophone ; le reste de
> la documentation technique est en anglais, comme le code.

---

## Modèle de sûreté

Cet outil supprime des enregistrements DNS. Lisez cette section avant d'exécuter quoi que ce soit
avec `--apply`.

| Garde-fou | Comportement |
|---|---|
| **Simulation par défaut** | `harden`, `harden-batch` et `restore` affichent un plan et ne modifient rien. `--apply` est nécessaire pour écrire. |
| **Sauvegarde avant toute écriture** | Toute exécution qui touche une zone l'exporte d'abord vers `storage/backups/<domaine>/<horodatage>.zone`. Rien n'est jamais écrasé. |
| **Garde « messagerie active »** | Une zone classée `mail-active` est refusée. La durcir casserait à la fois la réception et l'émission. |
| **`--force` est mono-domaine** | `harden-batch` refuse `--force` catégoriquement : une erreur ne peut pas se propager à tout un portefeuille. |
| **Redirections préservées** | Les enregistrements marqueurs de la redirection web OVH sont conservés sauf `--drop-redirect` explicite. |
| **Le CAA n'est jamais desserré** | Un CAA existant est laissé tel quel tant que `--caa` n'en republie pas un. Supprimer un CAA sans en publier rouvre l'émission à toutes les AC. |
| **`--keep <regex>`** | Protège ce que vous nommez : défis ACME, TXT de vérification de domaine, un MX précis. |
| **`restore`** | Réimporte la dernière sauvegarde d'une zone. |

> **Appliquer cette politique à un domaine qui émet du courrier cassera ce courrier.** Le
> classifieur est un bon filtre, pas un oracle : il lit le DNS, et le DNS ne peut pas prouver
> qu'aucune boîte aux lettres n'existe (voir [Classifieur](#classifieur)). Relisez le plan avant de
> l'appliquer.

---

## Prérequis

- **Node.js ≥ 20.12** (utilise `process.loadEnvFile` et le lanceur de tests intégré). Aucun
  `npm install` n'est nécessaire pour exécuter l'outil : les dépendances sont réservées au
  développement.
- Un compte OVHcloud dont les domaines utilisent le DNS d'OVH.

```bash
git clone https://github.com/yanis-git/ovh-domain-manager.git
cd ovh-domain-manager
node ovh.mjs --help
```

---

## Démarrage

### 1. Créer une application OVH

Rendez-vous sur la console API OVH de votre région et créez une application :

| Région | Créer l'application | Valeur du point d'accès |
|---|---|---|
| Europe | <https://eu.api.ovh.com/createApp/> | `ovh-eu` *(défaut)* |
| Canada | <https://ca.api.ovh.com/createApp/> | `ovh-ca` |
| États-Unis | <https://api.us.ovhcloud.com/createApp/> | `ovh-us` |

Vous obtenez une **clé d'application** et un **secret d'application**.

> Il s'agit du schéma clé d'application / clé de consommateur d'OVH, pas d'OAuth2. Chaque requête
> est signée avec `$1$sha1(secret + consumerKey + méthode + url + corps + horodatage)`. SHA-1 n'est
> pas un choix : c'est ce qu'impose l'API v1 d'OVH.

### 2. Renseigner les identifiants

```bash
cp .env.example .env
```

```ini
APP_KEY=votre_cle_application
APP_SECRET=votre_secret_application
OVH_CONSUMER_KEY=          # rempli à l'étape suivante
OVH_ENDPOINT=ovh-eu        # optionnel
```

`.env` est exclu du dépôt par `.gitignore`, et n'est jamais lu par la suite de tests.

### 3. Obtenir une clé de consommateur

```bash
node ovh.mjs auth
```

La commande affiche une URL de validation et une clé de consommateur. Ouvrez l'URL, connectez-vous,
confirmez — puis collez la clé dans `.env` sous `OVH_CONSUMER_KEY`.

La clé est demandée avec exactement ces droits, et aucun autre :

| Droit | Pourquoi |
|---|---|
| `GET /me` | `whoami`, pour confirmer sur quel compte vous êtes |
| `GET /domain/*` | lister les domaines, exporter les zones, lire les enregistrements |
| `POST /domain/zone/*` | créer des enregistrements, rafraîchir la zone, importer une sauvegarde |
| `PUT /domain/zone/*` | modifier des enregistrements |
| `DELETE /domain/zone/*` | supprimer des enregistrements |

Choisissez une validité courte quand OVH la demande, et révoquez la clé depuis l'espace client une
fois le travail terminé.

### 4. Vérifier

```bash
node ovh.mjs whoami
# Connected as: ab12345-ovh (vous@example.com)
```

---

## Inventaire du portefeuille

### Récupérer la liste des domaines

Exportez votre portefeuille depuis l'espace client OVH (**Noms de domaine → la liste → export CSV**)
et déposez le fichier dans `storage/`. L'outil lit la **première colonne** du CSV et ignore la ligne
d'en-tête : tout export dont la première colonne contient les domaines convient. Le CSV le plus
récent de `storage/` est utilisé, sauf si vous passez `--csv <chemin>`.

Vous pouvez aussi vous passer du CSV et nommer les domaines en ligne de commande.

### `snapshot` : récupérer, sauvegarder, classer

```bash
node ovh.mjs snapshot                  # tous les domaines du CSV
node ovh.mjs snapshot example.com      # un seul
```

Pour chaque domaine, la commande exporte la zone, écrit une sauvegarde horodatée, la classe, et
reconstruit `storage/inventory.md` et `storage/inventory.json`. Elle est **en lecture seule** vis-à-vis
d'OVH.

### L'inventaire est une liste de travail

`storage/inventory.md` regroupe les domaines par état, les dormants en premier, avec une case à
cocher par domaine. Cochez-les au fur et à mesure ; `harden --apply` les coche pour vous. **Les
cases cochées et leurs annotations sont préservées à chaque régénération.**

### Reconstruire hors ligne

```bash
node ovh.mjs inventory
```

Reclasse les sauvegardes déjà présentes sur le disque. Ni réseau, ni identifiants.

---

## Référentiel de conformité

```bash
node ovh.mjs compliance                  # tout le portefeuille
node ovh.mjs compliance example.com      # un seul domaine
```

Le classifieur répond à la question « ce domaine peut-il être durci sans risque ? ». Le référentiel
répond à une autre question : « quelle est la posture de sécurité de ce portefeuille, et quel est le
chemin le plus court pour l'améliorer ? » — avec vingt-quatre contrôles identifiés et pondérés,
chacun rattaché à une référence publiée.

Il s'exécute **hors ligne, à partir des sauvegardes déjà sur le disque** : aucun identifiant n'est
requis, et les mêmes sauvegardes produisent toujours le même score.

```
Compliance baseline v1.1.0 — 61 domain(s) from backups, offline

[  1/ 61] example.com                        B  86   spoof 100  closed  55  surface 100
[  2/ 61] other.example                      F  31   !! 3 critical failure(s)

== portfolio 78/100 (C) · A:5 B:12 C:15 D:6 F:2 · 1 without backup
   anti-spoofing 91 · closed by default 40 · attack surface 88
```

Trois artefacts sont écrits dans `storage/` : `compliance.md` pour une lecture humaine (uniquement
les écarts et les cas de jugement), `compliance.json` pour un traitement automatisé (tous les
résultats et les pondérations utilisées), et `compliance.csv` pour un auditeur — une ligne par
(domaine, contrôle), **succès inclus**, parce que la preuve de ce qui a été vérifié et jugé conforme
fait partie intégrante de l'audit.

### Comment un domaine est noté

Chaque contrôle appartient à un axe — **anti-usurpation**, **fermé par défaut**, **surface
d'attaque** — et chaque axe est noté séparément, afin qu'un portefeuille solide sur l'un et faible
sur l'autre ne puisse pas se cacher derrière une moyenne unique.

Les contrôles sont pondérés par sévérité (`critical` 10, `high` 6, `medium` 3, `low` 1). Le score
est le ratio pondéré des succès ; les notes vont de A (≥ 95) à F. Une seule règle non linéaire :
**la note est plafonnée à C dès qu'un contrôle critique échoue**, pour qu'une zone totalement
dépourvue de SPF ne puisse pas afficher un A grâce aux vingt contrôles qui passent. Le score du
portefeuille est la **moyenne non pondérée** des scores par domaine : une zone de quarante
enregistrements ne pèse pas plus que quarante zones vides.

### Chaque domaine jugé contre la posture attendue pour son état

L'audit couvre l'ensemble du portefeuille quel que soit l'état de chaque domaine — mais un domaine
qui émet légitimement du courrier n'est pas pénalisé parce qu'il publie une clé DKIM. Chaque
contrôle déclare une portée (`all`, `non-sending`, `sending`, `dormant`) et renvoie `n/a` en dehors.

`n/a` a un sens et un seul : **l'usage de la zone rend la question sans objet — jamais qu'un
enregistrement manque.** Un enregistrement manquant est un échec. Un `n/a` ne compte ni au
numérateur ni au dénominateur, et il est toujours affiché avec sa raison.

Les domaines sans sauvegarde exploitable sont signalés en erreur et **exclus de toutes les
moyennes**, jamais notés zéro : « non mesuré » et « mal mesuré » sont deux faits distincts.

Le catalogue complet est dans **[docs/BASELINE.md](docs/BASELINE.md)** *(en anglais)* ; la table de
correspondance vers l'ISO/IEC 27001:2022, NIS 2 et les guides de l'ANSSI est dans
**[docs/CONFORMITE.md](docs/CONFORMITE.md)**.

---

## Classifieur

Chaque zone est rangée dans l'un de quatre états.

| État | Signification | Durcissement sûr ? |
|---|---|---|
| `dormant` | Aucun signe d'usage messagerie ou web. | **Oui** — c'est la cible. |
| `web-active` | Sert du contenu web, messagerie probablement inutilisée. | Seulement après vérification. Le durcissement coupe l'émission depuis le domaine. |
| `mail-active` | Vrai prestataire de messagerie, ou clé DKIM publiée. | **Non.** Refusé sans `--force`. |
| `error` | Zone non hébergée chez OVH, ou injoignable. | Sans objet |

Ce que signale chaque indice :

| Indice | Se lit comme |
|---|---|
| MX vers Google Workspace, Microsoft 365, Mailgun/SendGrid/Mailjet…, OVH Exchange/Pro, Zoho/Proton/Fastmail… | `mail-active` |
| Hôte MX **non reconnu** | `mail-active` — sûreté avant tout : inconnu signifie « vérifiez vous-même » |
| MX vers les hôtes par défaut d'OVH (`mx1.mail.ovh.net`) | Pas concluant à soi seul — voir la réserve ci-dessous |
| MX nul (`0 .`, RFC 7505) | Ne reçoit explicitement aucun courrier |
| TXT `_domainkey` avec une vraie clé, ou CNAME `_domainkey` | `mail-active` — le domaine signe son courrier |
| TXT `_domainkey` avec `p=` vide | Clé révoquée — pas actif |
| Tout A/AAAA/CNAME hors de la plage de parking OVH | `web-active` |
| Enregistrement A sur `213.186.33.x` | Parking OVH — pas de contenu réel |

> **La réserve qu'il faut connaître.** Les boîtes MX Plan d'OVH utilisent les *mêmes* hôtes MX par
> défaut qu'un domaine non configuré. Le DNS seul ne peut donc pas prouver qu'aucune boîte aux
> lettres n'existe. Un domaine affiché `dormant` avec un MX OVH par défaut peut encore avoir une
> messagerie réelle : vérifiez dans l'espace client si c'est plausible pour votre compte.

---

## Sauvegarde et restauration

Chaque `snapshot`, chaque plan et chaque application écrit d'abord un export complet de la zone :

```
storage/backups/<domaine>/2026-09-09T11-35-36-671Z.zone
```

Les sauvegardes sont en ajout seul — rien ne les élague et rien n'est écrasé. Ce sont des fichiers
de zone au format BIND, lisibles et comparables.

```bash
node ovh.mjs restore example.com                    # simulation
node ovh.mjs restore example.com --apply            # réimporte la dernière sauvegarde
```

---

## Durcissement (`harden`)

### Ce qui est publié

| Enregistrement | Valeur | Pourquoi |
|---|---|---|
| `TXT @` | `v=spf1 -all` | Aucun hôte au monde n'est autorisé à émettre pour ce domaine. `-all` est un échec dur, pas `~all`. |
| `TXT _dmarc` | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s` | Les destinataires rejettent les échecs, sous-domaines compris, en alignement strict. |
| `TXT *._domainkey` | `v=DKIM1; p=` | Révocation par joker : tout sélecteur DKIM est déclaré sans clé. |
| `MX @` | `0 .` | *Optionnel, `--null-mx`.* RFC 7505 : le domaine n'accepte aucun courrier. OVH peut refuser cet enregistrement. |
| `CAA @` | `0 issue ";"` / `0 issuewild ";"` | *Optionnel, `--caa`.* RFC 8659 : aucune autorité de certification ne peut émettre pour ce domaine. |

Ajoutez `--rua mailto:vous@example.com` pour recevoir les rapports agrégés DMARC, et
`--iodef mailto:vous@example.com` pour les rapports de violation CAA (implique `--caa`).

> **`--caa` est optionnel, et à lire avant usage.** Une interdiction CAA à l'apex est héritée par
> **tous** les sous-domaines (RFC 8659) et empêchera le renouvellement d'un certificat — 60 à 90
> jours plus tard, pas au moment de la publication. `harden` refuse de la publier sur une zone
> `web-active`, sur une zone portant une redirection OVH, sur une zone dont l'apex ou `www` résout
> encore vers un hôte vivant, ou pendant qu'un `_acme-challenge` est en cours, et affiche à la place
> `caa : skipped — <raison>`.
>
> **La syntaxe du champ `target` pour `fieldType: CAA` chez OVH n'est pas documentée et n'a pas été
> vérifiée contre un compte réel.** La valeur publiée est la forme « fichier de zone ». Confirmez-la
> sur une zone jetable que vous pouvez restaurer avant votre premier `--apply --caa` : si OVH refuse
> l'enregistrement, l'exécution signale une erreur de création et la zone se retrouve **sans** CAA —
> plus permissive qu'avant, pas cassée, et `restore` la remet en état.

Un CAA existant n'est jamais supprimé par un `harden` ordinaire. Sans `--caa` il apparaît en
`. KEEP … -> CAA out of scope (pass --caa)`, parce que supprimer un CAA sans en publier un rouvre
l'émission de certificats à toutes les autorités de la planète.

### Ce qui est supprimé

Uniquement des enregistrements de l'apex, là où la politique publie : `@`, `_dmarc` et
`<sélecteur>._domainkey`.

- Les `MX` de l'apex (un domaine dormant n'en a pas besoin).
- Les `TXT`/`SPF`/`DKIM`/`DMARC` de l'apex, remplacés par la politique ci-dessus.
- Le CNAME `ftp` (ajoutez-en avec `--drop-cname webmail,autodiscover`).

### Ce qui est délibérément laissé en place

- **Les marqueurs de redirection web OVH** — des TXT de la forme `3|www.example.com`. Ce sont des
  rouages du service de redirection d'OVH, sans rapport avec le courrier ; les supprimer seuls casse
  la redirection. Passez `--drop-redirect` si vous voulez vraiment les retirer.
- **Tout ce qui correspond à `--keep`** — expression régulière répétable, appliquée au nom de
  l'enregistrement comme à sa valeur :
  ```bash
  node ovh.mjs harden example.com --keep 'site-verification' --keep '_acme-challenge'
  ```
- **Tout ce qui se trouve sur un sous-domaine.** Un domaine qui route son courrier par
  `mg.example.com` conserve `mg MX`, `mg TXT "v=spf1 include:…"`, `_dmarc.mg` et
  `email._domainkey.mg` : aucun de ces noms n'appartient à la politique de l'apex, donc durcir
  l'apex laisse ce courrier fonctionner. Revers de la médaille : la posture de ce sous-domaine
  reste à auditer séparément.
- Les A/AAAA/CNAME autres que ceux listés ci-dessus : hors périmètre, intacts.

### Un domaine

```bash
node ovh.mjs harden example.com              # simulation
node ovh.mjs harden example.com --apply
```

Relancée sur une zone déjà durcie, la commande affiche `OK zone already compliant, nothing to do` :
le plan est idempotent, un enregistrement conforme n'est ni supprimé ni recréé.

### En lot

```bash
node ovh.mjs harden-batch --list storage/batch.txt            # simulation
node ovh.mjs harden-batch --list storage/batch.txt --apply
```

Le mode lot itère avec une pause de 300 ms entre les domaines (le client n'a ni réessai ni
temporisation exponentielle), **ignore toute zone `mail-active`**, refuse `--force`, et ne laisse
jamais une zone en échec interrompre l'exécution.

---

## Référence des commandes

| Commande | Réseau | Écrit chez OVH | Description |
|---|---|---|---|
| `auth` | oui | non | Obtenir une clé de consommateur |
| `whoami` | oui | non | Afficher le compte authentifié |
| `snapshot [domaines…]` | oui | non | Exporter + sauvegarder + classer |
| `inventory [domaines…]` | **non** | non | Reconstruire l'inventaire depuis les sauvegardes |
| `compliance [domaines…]` | **non** | non | Évaluer le portefeuille contre le référentiel |
| `audit <domaine>` | oui | non | Afficher la zone en production |
| `harden <domaine>` | oui | seulement avec `--apply` | Planifier/appliquer la politique sur un domaine |
| `harden-batch` | oui | seulement avec `--apply` | Idem sur une liste |
| `restore <domaine> [fichier]` | oui | seulement avec `--apply` | Réimporter une sauvegarde |

| Option | Défaut | Description |
|---|---|---|
| `--apply` | off | Exécuter réellement. Sans elle, tout est une simulation. |
| `--force` | off | Contourner la garde « messagerie active ». `harden` mono-domaine uniquement. |
| `--null-mx` | off | Publier aussi `MX 0 .` (RFC 7505). |
| `--caa` | off | Publier aussi une interdiction CAA (RFC 8659). **Optionnel — lire l'avertissement.** |
| `--iodef <mailto:…>` | aucune | Adresse de rapport de violation CAA. Implique `--caa`. |
| `--rua <mailto:…>` | aucune | Adresse de rapport agrégé DMARC. |
| `--keep <regex>` | aucune | Protéger les enregistrements correspondants. Répétable. |
| `--drop-cname a,b` | `ftp` | CNAME supplémentaires à supprimer. |
| `--drop-redirect` | off | Supprimer aussi les marqueurs de redirection OVH. **Casse la redirection.** |
| `--csv <chemin>` | le plus récent dans `storage/` | CSV source. |
| `--list <chemin>` | aucun | Fichier de lot pour `harden-batch`. |
| `--ttl <secondes>` | `3600` | TTL des enregistrements créés. |

| Variable d'environnement | Défaut | Description |
|---|---|---|
| `APP_KEY` | — | Clé d'application OVH **(requise)** |
| `APP_SECRET` | — | Secret d'application OVH **(requis)** |
| `OVH_CONSUMER_KEY` | — | Clé de consommateur, issue de `auth` |
| `OVH_ENDPOINT` | `ovh-eu` | `ovh-eu`, `ovh-ca` ou `ovh-us` |
| `OVH_STORAGE_DIR` | `./storage` | Où sont écrits sauvegardes, rapports et inventaire |
| `OVH_ENV_FILE` | `./.env` | Fichier d'identifiants à charger |

---

## Dépannage

**`Zone "x" not found at OVH (DNS delegated elsewhere?)`** — le domaine est enregistré chez OVH mais
son DNS est hébergé ailleurs : il n'y a pas de zone OVH à modifier.

**`OVH 403 … Invalid signature`** — en général un décalage d'horloge. Le client appelle `/auth/time`
et corrige automatiquement ; si cela persiste, vérifiez que votre clé de consommateur est validée et
non expirée.

**OVH refuse le MX nul** — certaines zones rejettent `MX 0 .`. C'est optionnel, retirez `--null-mx`.
SPF `-all` et DMARC `p=reject` suffisent déjà à bloquer l'usurpation ; le MX nul ne concerne que le
courrier *entrant*.

**Un certificat Let's Encrypt ne se renouvelle plus** — vous avez publié une interdiction CAA avec
`--caa` sur une zone qui a encore besoin de certificats. Restaurez la zone
(`node ovh.mjs restore <domaine> --apply`) ou supprimez les CAA dans l'espace client OVH. L'outil
s'efforce d'éviter ce cas, mais il lit le DNS, et le DNS ne voit pas un certificat que vous émettez
depuis ailleurs. C'est la raison pour laquelle `--caa` est optionnel.

**Une redirection web ne fonctionne plus** — vous avez passé `--drop-redirect`. Restaurez la zone ou
recréez la redirection dans l'espace client.

**Un domaine durci apparaît en `mail-active`** — regardez les indices dans l'inventaire. Un CNAME
`_domainkey` résiduel (délégation DKIM d'OVH MX Plan) en est la cause habituelle ; c'est un CNAME,
donc la politique ne le supprime pas. Supprimez-le dans l'espace client si la boîte a réellement
disparu.

---

## Développement

```bash
npm install     # dépendances de développement uniquement (ESLint)
npm test        # node --test, sans réseau, sans identifiants
npm run lint
```

La suite de tests ne contacte jamais OVH : les tests unitaires neutralisent `fetch`, et les tests
de bout en bout s'exécutent avec `OVH_ENV_FILE` pointant vers un fichier inexistant, de sorte que
votre `.env` réel ne peut jamais être utilisé.

Voir [AGENTS.md](AGENTS.md) pour l'architecture et les invariants à préserver,
[docs/POLICY.md](docs/POLICY.md) pour le raisonnement derrière la politique DNS,
[docs/BASELINE.md](docs/BASELINE.md) pour le catalogue des contrôles,
[docs/CONFORMITE.md](docs/CONFORMITE.md) pour la correspondance réglementaire, et
[CONTRIBUTING.md](CONTRIBUTING.md) pour contribuer.

## Sécurité

Les identifiants vivent dans `.env` et ne quittent jamais votre machine. Voir
[SECURITY.md](SECURITY.md) pour la manière de restreindre et révoquer une clé de consommateur, et
pour signaler une vulnérabilité.

## Licence

[MIT](LICENSE) © Yanis Ghidouche
