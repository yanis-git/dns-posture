# Conformité — correspondance contrôle ↔ exigence

Document de travail destiné à un RSSI, un DPO ou un auditeur. Il met en regard les vingt-trois
contrôles de `node ovh.mjs compliance` et les référentiels qui les motivent : ISO/IEC 27001:2022,
la directive NIS 2, et les guides de l'ANSSI.

Le catalogue technique des contrôles est dans [BASELINE.md](BASELINE.md) *(en anglais, comme la
sortie de l'outil)*. Le raisonnement derrière les enregistrements publiés est dans
[POLICY.md](POLICY.md).

> **Avertissement de portée.** Cet outil mesure ce que le DNS d'un domaine déclare. Il ne constate
> ni la conformité d'une organisation, ni la mise en œuvre d'une mesure de sécurité : il fournit un
> élément de preuve technique, daté et reproductible, à verser à un dossier. Un score de 100 ne
> signifie pas « conforme ISO 27001 » ; il signifie que la posture DNS de ce domaine correspond à
> celle attendue pour son état.

---

## Les trois axes et ce qu'ils couvrent

### 1. Réduction de la surface d'attaque du SI

Un portefeuille de domaines est une surface d'attaque que personne ne cartographie. Les domaines
achetés pour une campagne terminée, une marque abandonnée ou une faute de frappe défensive
continuent de résoudre, de porter des sous-domaines de service, et parfois de déléguer un nom vers
une plateforme tierce dont l'inscription a expiré.

Les contrôles `wildcard.none`, `services.no-legacy`, `srv.none`, `cname.no-takeover` et
`txt.no-stale-verification` recensent ce qui reste exposé sans usage : un joker DNS qui fait
résoudre tout nom inventé, un `autodiscover` qui annonce encore une messagerie disparue, une
vérification de service tierce jamais révoquée, un CNAME vers un compte d'hébergement qui peut être
réenregistré par un tiers.

### 2. Posture « fermé par défaut »

Un domaine inutilisé ne devrait rien permettre par omission. Or l'absence d'enregistrement est, en
DNS, une autorisation implicite : sans CAA, **toute** autorité de certification du monde peut
émettre un certificat pour le domaine ; sans MX nul, le domaine reste ambigu vis-à-vis du courrier
entrant.

Les contrôles `mx.closed`, `mx.null-explicit`, `caa.issue-deny`, `caa.issuewild-deny`,
`caa.present` et `caa.no-permissive` vérifient que la fermeture est **énoncée**, et pas seulement
subie. C'est la différence entre « rien n'est configuré » et « il est déclaré que rien n'est
autorisé » — la seconde formulation est opposable, la première est un oubli.

### 3. Protection anti-usurpation d'identité renforcée

C'est le cœur historique de l'outil. Un domaine dormant sans SPF ni DMARC permet à quiconque
d'émettre du courrier avec un `From:` à votre nom — fausse facture, réinitialisation de mot de
passe, hameçonnage de vos clients — et ces messages passent les contrôles de base.

`spf.present`, `spf.single`, `spf.hardfail`, `dmarc.present`, `dmarc.reject`,
`dmarc.subdomain-reject`, `dmarc.strict-alignment`, `dkim.wildcard-revoked` et
`dkim.no-live-selector` vérifient que l'interdiction est complète et sans échappatoire. Pour les
domaines qui émettent légitimement, `spf.no-permissive`, `spf.lookup-budget` et
`dkim.selector-published` vérifient l'inverse : que l'autorisation est étroite et fonctionnelle.

---

## Correspondance

### ISO/IEC 27001:2022 — Annexe A

| Mesure | Intitulé | Contrôles concernés | Lien |
|---|---|---|---|
| **A.5.9** | Inventaire des informations et autres actifs associés | `services.no-legacy`, `cname.no-takeover`, `txt.no-stale-verification` — et l'inventaire de portefeuille lui-même (`inventory`) | Un domaine est un actif. Les sous-domaines résiduels sont des actifs non recensés. |
| **A.5.14** | Transfert d'informations | `spf.*`, `dmarc.*`, `dkim.*` | La messagerie est le canal de transfert le plus exposé ; SPF/DKIM/DMARC en sont les mesures d'authentification. |
| **A.8.9** | Gestion des configurations | La politique de durcissement versionnée et le caractère idempotent du plan | La configuration DNS cible est définie dans le code, appliquée de façon reproductible, et vérifiable a posteriori. |
| **A.8.13** | Sauvegarde des informations | La sauvegarde de zone systématique avant toute mutation, et `restore` | Aucune écriture n'a lieu sans export préalable de la zone complète. |
| **A.8.20** | Sécurité des réseaux | `mx.closed`, `wildcard.none` | Ce qui est joignable et par quelle route. |
| **A.8.21** | Sécurité des services en réseau | `caa.issue-deny`, `caa.issuewild-deny`, `caa.present` | L'émission de certificats est un service réseau dont l'autorisation doit être restreinte. |

### Directive (UE) 2022/2555 (NIS 2)

| Article | Objet | Contrôles concernés |
|---|---|---|
| **Art. 21(2)(a)** | Politiques d'analyse des risques et de sécurité des SI | `cname.no-takeover` et, plus largement, la cartographie produite par `inventory` et `compliance` |
| **Art. 21(2)(e)** | Sécurité de l'acquisition, du développement et de la maintenance | Le cycle de vie des domaines : un domaine acquis pour un projet clos doit être fermé, pas seulement oublié |
| **Art. 21(2)(g)** | Pratiques d'hygiène informatique de base | `spf.present`, `dmarc.present`, `dmarc.reject` — l'authentification du courrier est une mesure d'hygiène élémentaire |

> **Sur la portée juridique.** NIS 2 s'applique aux entités essentielles et importantes au sens de
> la directive. La transposition française est portée par l'ANSSI et son dispositif d'application
> se met en place ; les exigences citées ici sont donc à lire comme un cadre de référence, et non
> comme une obligation dont le détail serait déjà stabilisé. Vérifiez votre propre assujettissement
> avant de vous en prévaloir dans un dossier.

### Recommandations de l'ANSSI

| Guide | Référence | Ce qu'il couvre ici |
|---|---|---|
| *Recommandations relatives aux architectures des services DNS* | **ANSSI-PA-105**, 17/07/2024 | L'architecture et l'hygiène du service DNS : cohérence de la zone, maîtrise des délégations, suppression des enregistrements résiduels. |
| *Recommandations relatives à l'interconnexion d'un système d'information à Internet* | **ANSSI-PA-066** v3.0, 19/06/2020 | Le chapitre messagerie couvre MX, SPF, DKIM et DMARC ; le principe de réduction des points d'exposition couvre les axes 1 et 2. |
| *Guide d'hygiène informatique* (42 mesures) | ANSSI | La cartographie du système d'information et la maîtrise des noms de domaine comme mesures de base. |

> **⚠️ À confirmer — numéros de recommandation.** Les guides ci-dessus sont vérifiés (titre,
> référence, date). En revanche les **numéros de recommandation individuels** (`R1`, `R2`, …)
> n'ont pas été relevés dans les PDF officiels et ne sont donc **volontairement pas cités** dans ce
> document ni dans le champ `refs` du référentiel. Un artefact de conformité qui cite une référence
> fausse est pire qu'un artefact qui n'en cite aucune. Pour compléter cette table, relevez les
> numéros dans les documents officiels sur [cyber.gouv.fr](https://cyber.gouv.fr/) et ajoutez-les
> au champ `refs` de `lib/baseline.mjs` — c'est une donnée, sa correction ne touche pas au code.

---

## Ce que l'outil ne prouve pas

Énoncé explicitement, parce qu'un rapport d'audit qui ne borne pas sa propre portée est trompeur.

1. **Le DNS ne prouve pas l'absence de boîte aux lettres.** Les MX par défaut d'OVH sont les mêmes
   pour un domaine non configuré et pour un domaine avec des boîtes MX Plan. Un domaine classé
   `dormant` peut encore avoir une messagerie réelle : vérifiez dans l'espace client avant de
   durcir.
2. **Le score porte sur une sauvegarde, pas sur le DNS en production.** Il reflète l'état au moment
   du dernier `snapshot`. La date de la sauvegarde est indiquée pour chaque domaine dans le
   rapport.
3. **`cname.no-takeover` ne constate pas une prise de contrôle.** Hors ligne, il est impossible de
   savoir si la cible est encore revendiquée. Le constat invite à vérifier ; il n'affirme rien.
4. **Un score n'est comparable qu'à version de référentiel égale.** `BASELINE_VERSION` est inscrite
   dans chaque rapport ; un changement de pondération modifie un score sans qu'aucun DNS n'ait
   bougé.
5. **La conformité organisationnelle n'est pas mesurée.** Politiques, gouvernance, sensibilisation,
   gestion des incidents : hors périmètre d'un outil qui lit des zones DNS.

---

## Produire une preuve d'audit

```bash
node ovh.mjs snapshot          # rafraîchit les sauvegardes depuis OVH (lecture seule)
node ovh.mjs compliance        # évalue le portefeuille, hors ligne
```

`storage/compliance.csv` est le livrable : une ligne par (domaine, contrôle), **succès inclus** —
la preuve de ce qui a été vérifié et jugé conforme fait partie de l'audit, au même titre que les
écarts. Les colonnes sont stables (`domain,state,score,grade,control,title,axis,severity,scope,
status,detail,refs,remediation`), donc filtrables dans un tableur.

`storage/compliance.json` porte en plus les pondérations utilisées, la version du référentiel et
l'horodatage, de quoi rejouer le calcul.

> **Ces trois fichiers contiennent des données opérationnelles** — noms de sous-domaines réels,
> jetons de vérification cités mot pour mot. Ils sont exclus du dépôt par `.gitignore` et la CI
> échoue si l'un d'eux est suivi par Git. Traitez-les comme le reste de `storage/`.
