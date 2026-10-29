# Portage GAYA vers MailDev 3.0.0

La branche locale `gaya-3.0.0` repart du tag officiel `maildev@3.0.0`
(`e1ddfdbd3f156d56efd7d612b85b042dd0fdeed7`). Les branches historiques du
fork restent intactes. La v3 étant une réécriture en TypeScript, les comportements
utiles sont portés dans les nouveaux paquets plutôt que de réappliquer les anciens
fichiers `lib/*.js`.

## Bilan des 19 correctifs du fork

| Commit    | Sujet                                             | Résultat sur cette branche                                                                                                                                                         |
| --------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `af5baa3` | Pas de relais automatique au rechargement         | Déjà couvert par `saveEmail(..., isRestored)` en v3 ; testé aussi en virtualhost.                                                                                                  |
| `7556311` | Date lors du rechargement                         | La v3 garantit une date ; complété ici par la date du fichier si le message restauré n'a pas d'en-tête `Date`, pour ne pas réinitialiser son âge.                                  |
| `09a75db` | Suppression automatique par âge                   | Réintroduite avec `--auto-delete` / `MAILDEV_AUTO_DELETE`, en heures. `maxEmails` en v3 ne remplace pas cette rétention.                                                           |
| `0851c7e` | Virtualhosts                                      | Réintroduits dans le stockage, SMTP, toutes les routes de messages, les pièces jointes et Socket.IO. Les sessions MCP sont aussi liées à leur hôte.                                |
| `946d57a` | Filtrage des domaines                             | Réintroduit avec `--domain-filter-rules` / `MAILDEV_DOMAIN_FILTER_RULES`, sur le nom SMTP EHLO.                                                                                    |
| `08c85d1` | Documentation des options du fork                 | Remplacée par le présent bilan et l'aide CLI mise à jour.                                                                                                                          |
| `25ef65e` | Expéditeur dans l'aperçu de liste                 | Non couvert par la liste React v3 ; ajouté dans `EmailListItem`, sans retirer le destinataire.                                                                                     |
| `6693f0f` | Crash de la suppression planifiée                 | L'ancien ordonnanceur a disparu. La rétention ajoutée ici sérialise ses exécutions et s'arrête proprement avec SMTP.                                                               |
| `a5d2bbd` | Expéditeur invalide au rechargement               | Couvert par le parseur et la reconstruction d'enveloppe v3.                                                                                                                        |
| `4579250` | « Relay To » altère les destinataires stockés     | Encore présent en v3 ; corrigé par une copie avant remplacement et une persistance du seul résultat de relais sur le message d'origine.                                            |
| `7b8cce4` | Distinguer filtrage et véritable erreur de relais | Principe couvert : aucun destinataire après filtrage n'est pas traité comme une erreur SMTP. Les formats de logs v3 sont conservés.                                                |
| `74d3911` | Diagnostics de restauration                       | Déjà présents en v3, avec poursuite du chargement après un fichier illisible.                                                                                                      |
| `f7c9de1` | Refactorisation et gestion d'erreurs v2           | Ancien code remplacé par l'architecture async/await v3.                                                                                                                            |
| `0829749` | Message sans `From` et enveloppe persistée        | L'absence de `From` reste gérée ; les enveloppes SMTP sont conservées dans des `.evl` et restaurées, y compris pour les messages sans `From`.                                      |
| `2b5f05e` | Modernisation Docker/Compose                      | Remplacée par le Dockerfile multi-stage v3, dont la cible `prod` reste utilisable.                                                                                                 |
| `1a2f56c` | JSON d'enveloppe invalide                         | Un `.evl` absent ou invalide est ignoré sans bloquer la restauration depuis le `.eml` ; les métadonnées de relais `.meta.json` gardent leur propre repli.                          |
| `f48365d` | Échec du serveur relais distant                   | Le traitement v3 était incomplet : l'événement d'erreur ne rejetait pas la connexion. Corrigé ici, avec fermeture du flux brut et test d'erreur HTTP sans modification du message. |
| `b24dae4` | Compatibilité de l'ancienne API interne           | Anciennes interfaces remplacées par les paquets v3 ; les appels ont été adaptés à leurs nouvelles signatures.                                                                      |
| `f0a0d1a` | Relais depuis un virtualhost                      | Réintroduit : recherche, source brute et état de relais utilisent le même compartiment d'hôte.                                                                                     |

## Fonctionnement des virtualhosts

- Le client SMTP doit annoncer le domaine virtuel dans son nom EHLO/HELO
  (`name` avec Nodemailer). Le navigateur et le proxy HTTP doivent conserver le
  même domaine dans `Host`.
- La sélection est insensible à la casse, retire le port HTTP et le point DNS
  final. Les valeurs pouvant devenir des chemins de fichiers sont refusées.
- Avec `MAILDEV_MAIL_DIRECTORY=/data`, un domaine `site.test.gaya.fr` utilise
  `/data/site.test.gaya.fr/` pour ses `.eml`, pièces jointes et métadonnées.
- Listes, compteurs, lecture, suppression, téléchargements, relais et événements
  temps réel sont limités à ce domaine. La limite `maxEmails` est par domaine.
- Le mode est désactivé par défaut. Sans `--virtual-host`, le stockage v3 habituel
  reste utilisé.

Ce cloisonnement n'est **pas une authentification** : un client choisit son EHLO
ou son en-tête `Host`. Il faut donc conserver les contrôles d'accès réseau/proxy
et, si nécessaire, l'authentification SMTP/HTTP. Les règles de domaine limitent
les noms acceptés mais ne prouvent pas leur identité.

## Options GAYA conservées

| CLI                            | Variable                      | Valeur/définition                                                                                                |
| ------------------------------ | ----------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `--virtual-host`               | `MAILDEV_VIRTUAL_HOST`        | Booléen, désactivé par défaut.                                                                                   |
| `--domain-filter-rules <file>` | `MAILDEV_DOMAIN_FILTER_RULES` | Fichier JSON de règles `allow`/`deny` ordonnées, avec `*`, sur EHLO. La dernière règle correspondante l'emporte. |
| `--auto-delete <hours>`        | `MAILDEV_AUTO_DELETE`         | Entier positif en heures ; `0` désactive. Nettoyage après restauration puis au plus toutes les heures.           |

Les règles existantes commençant par `{ "deny": "*" }`, puis autorisant
`*.test.gaya.fr` ou `*.local`, restent utilisables. La rétention de `168` heures
du Compose correspond à sept jours. Elle utilise la date du message ; au
rechargement d'un message sans date MIME, la date du fichier est conservée.

## Déploiement et persistance

Le contexte `../maildev`, la cible Docker `prod`, les ports `1080`/`1025`,
`MAILDEV_MAIL_DIRECTORY=/data` et `MAILDEV_BASE_PATHNAME=/maildev` restent valides.
L'image v3 utilise Node 22 et le workspace utilise pnpm 10.34.4.

Deux différences à prendre en compte avant le déploiement :

1. Le volume historique
   `./runtime/conf/maildev/main.html:/home/node/app/views/main.html` ne personnalise
   plus l'interface : la v3 sert l'application React compilée de `@maildev/ui`.
   Retirer ce montage ou reporter ses personnalisations dans `packages/ui`.
   Le Compose du projet parent n'a pas été modifié par ce portage.
2. Les `.eml` et leurs `.evl` sont restaurés ensemble. Les `.evl` historiques
   conservent l'enveloppe SMTP (IP cliente, virtualhost et destinataires BCC) ;
   les nouvelles réceptions en écrivent également. Si un `.evl` manque ou est
   invalide, MailDev retombe sur les en-têtes du `.eml`. Les `.meta.json` conservent
   désormais `relayHistory`, avec une entrée par relais réussi, ainsi que
   `relayedAt`/`relayedTo` pour le dernier succès. Un ancien fichier ne contenant
   que ces deux champs est lu comme un historique d'une entrée : les relais plus
   anciens déjà écrasés ne peuvent pas être reconstitués. Au chargement, un `.evl`
   ou `.meta.json` sans fichier `.eml` régulier correspondant dans son répertoire
   est supprimé ; cette vérification est faite même si le message ne fait pas
   partie de la sélection `maxEmails`.
3. Les mises à jour du sidecar sont sérialisées dans le processus et écrites dans
   un fichier temporaire synchronisé avant son renommage atomique ; cela évite les
   pertes et JSON partiels quand plusieurs utilisateurs relaient simultanément.
   Cette garantie ne couvre pas plusieurs processus MailDev partageant le même
   volume. Après chaque persistance, Socket.IO notifie les clients du virtualhost
   concerné ; leur détail du message est relu pour afficher l'historique actualisé.

## Vérification

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm build
pnpm exec turbo run test --concurrency=1
docker build --target prod -t maildev:gaya-3.0.0 .
```

Validation effectuée : les 411 tests des six paquets passent et l'image de
production est construite. Son scénario de fumée sous `/maildev`, avec les
règles `*.local` et la rétention de 168 heures, valide l'interface, le contrôle
de santé, deux réceptions SMTP séparées, le refus d'une lecture croisée, la
suppression limitée à un hôte et la persistance de l'autre après redémarrage.

L'exécution séquentielle des paquets évite de faire concourir le test de
performance de `MemoryStorage` avec les autres suites ; aucun seuil de ce test
n'a été modifié. Les régressions ajoutées couvrent les hôtes A/B, les chemins
disque, la restauration, la rétention, les téléchargements et relais croisés,
les notifications, MCP, le relais en erreur, la conservation des destinataires
et l'aperçu expéditeur.
