# dns-posture

[English](README.md) · [Commandes](docs/COMMANDS.md) · [Migration](docs/MIGRATION.md)

**Protéger l’identité de votre entreprise dans les courriels.** Un domaine peut être affiché comme expéditeur d’un faux message même s’il ne possède aucune boîte mail. dns-posture examine les configurations OVHcloud et Cloudflare, signale les protections manquantes et prépare les corrections des domaines qui ne doivent pas envoyer de messages. Aucune dépendance runtime. **La simulation est le mode par défaut.**

Comprendre l’enjeu : **[Un courriel peut emprunter le nom de votre entreprise](https://fennec.sh/blog/domaines-oublies-responsabilite)**, avec les recommandations de l’ANSSI expliquées simplement. Puis découvrir **[un exemple de rapport et le suivi périodique des domaines](https://fennec.sh/blog/nettoyer-portefeuille-dns)**. Ces articles détaillent la protection et ses limites pour un dirigeant non spécialiste.

[Package npm](https://www.npmjs.com/package/dns-posture) · [Code sur GitHub](https://github.com/yanis-git/dns-posture) · [Configurer le reporting et le suivi](docs/MONITORING.md)

## Installation

Node 22.14 ou ultérieur :

```sh
npx dns-posture --help
```

L’exécutable historique `ovh-domain-manager` et `node ovh.mjs` restent disponibles.

## Configuration

Créer un `.env` dans le dossier de lancement, ou utiliser des variables d’environnement :

```dotenv
# OVH (fournisseur par défaut)
APP_KEY=your-application-key
APP_SECRET=your-application-secret
OVH_CONSUMER_KEY=your-consumer-key
OVH_ENDPOINT=ovh-eu
# Cloudflare : token dédié, limité aux zones concernées
CLOUDFLARE_API_TOKEN=your-api-token
```

Création du consumer key OVH : `npx dns-posture auth`. Cloudflare nécessite Zone Read et DNS Read, puis DNS Edit pour appliquer les changements. Ajouter `--provider cloudflare` à chaque commande pour le sélectionner.

Le stockage est `./storage`, relatif au dossier de lancement et séparé par fournisseur/compte/zone. `DNS_POSTURE_STORAGE_DIR`, `DNS_POSTURE_ENV_FILE` et `DNS_POSTURE_POLICY_FILE` permettent de choisir les chemins. Les alias historiques `OVH_*` restent acceptés. Une politique est un module JavaScript de confiance exécuté au chargement. Garder les exceptions opérationnelles hors du package installé.

## Observer, prévoir, appliquer, vérifier

```sh
npx dns-posture zones
npx dns-posture snapshot example.com
npx dns-posture audit example.com
npx dns-posture compliance example.com
npx dns-posture policy example.com
npx dns-posture harden example.com
npx dns-posture harden example.com --apply
npx dns-posture audit example.com
npx dns-posture restore example.com /path/to/before.json
# Examiner le différentiel avant d’ajouter --apply à restore.
```

Inventaire, conformité et prévisualisation de politique utilisent les sauvegardes entièrement hors ligne. Chaque application, restauration comprise, sauvegarde l’état courant complet, verrouille localement la zone et compare les enregistrements du fournisseur avant et après écriture. Une erreur arrête les écritures sur la zone. Codes de sortie : **0 succès vérifié, 1 erreur/refus, 2 application partielle/incertaine**. Le batch poursuit les autres zones.

## Limites et documentation

La propagation DNS n’est pas atomique. Les verrous locaux n’empêchent pas une intervention distante. Les écritures CAA OVH sont bloquées tant que leur encodage API n’est pas validé. Null MX et interdiction CAA sont activables explicitement. Les sauvegardes JSON versionnées conservent les métadonnées natives pour la restauration. Les anciens `.zone` restent lisibles hors ligne, mais ne permettent pas une restauration automatique vérifiée. Paramètres du compte, DNSSEC et services externes restent hors périmètre.

[Audit de sûreté](docs/AUDIT-1.0.md) · [Politique](docs/POLICY.md) · [Référentiel](docs/BASELINE.md) · [Publication npm](docs/RELEASING.md)


Développement : `npm ci`, `npm test`, `npm run lint`, `npm run test:pack`. Les tests simulent les API sans credentials réels ni écriture DNS. Licence MIT.
