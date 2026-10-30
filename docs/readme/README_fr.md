<div align="center">

# Anti-REA

### Un serveur MCP pour durcir vos propres logiciels contre la rétro-ingénierie pilotée par agent

**Auditez ce que divulguent vos artefacts livrés. Appliquez les mesures d'atténuation. Vérifiez le résultat.**

[![Licence : MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](../../LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933.svg)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-5c4ee5.svg)](#connecter-votre-agent)
[![Tests](https://img.shields.io/badge/tests-node--test-5c4ee5.svg)](#vérification)

[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Deutsch](README_de.md) · **Français** · [Español](README_es.md) · [Português (Brasil)](README_pt-BR.md) · [Русский](README_ru.md) · [Italiano](README_it.md)

Node.js sans aucune dépendance. Tout s'exécute en local. Nécessite Node.js 22 ou une version plus récente.

[Fonctionnement](#fonctionnement) · [Démarrage rapide en ligne de commande](#démarrage-rapide-en-ligne-de-commande) · [Ce que l'audit rapporte](#ce-que-laudit-rapporte) · [Résultats mesurés](#résultats-mesurés) · [Couches de défense](#couches-de-défense) · [Limites connues](#limites-connues) · [FAQ](#faq) · [Vérification](#vérification) · [Contribution](#contribution) · [Sécurité](#sécurité)

</div>

---

> [!IMPORTANT]
> Ne vous procurez Anti-REA qu'auprès de ce dépôt. Il n'existe pas encore de publication
> npm, et un paquet au nom semblable ne garantit pas qu'un téléchargement soit officiel.
> N'utilisez l'outil que sur des logiciels dont vous êtes propriétaire ou que vous êtes
> autorisé à protéger.

REA (Reverse Engineer Anything) et les chaînes d'outils comparables fondées sur MCP permettent
à un agent d'intelligence artificielle d'inspecter un binaire, un paquet ou une application
livrés sans disposer de leur code source, d'expliquer le fonctionnement d'une fonctionnalité et
d'en produire une réplique. Le coût de compréhension des logiciels que vous livrez s'en trouve
ramené tout près de zéro.

Anti-REA est la contrepartie du défenseur. C'est un serveur MCP, doublé d'une interface en
ligne de commande qui partage les mêmes flux de travail, et qui durcit **votre propre projet**
avant sa livraison :

- **audit_artifact** : ce qu'un artefact livré expose aux lecteurs et aux moteurs qu'emploient
  ces outils, avec la preuve et la plage source qui sous-tend chaque fait
- **harden_artifact** : applique les mesures d'atténuation que l'outil peut appliquer, et
  signale celles qui exigent des outils externes ou une modification d'architecture
- **verify_artifact** : confirme que les mesures d'atténuation tiennent
- **generate_notice** : un texte de licence et d'interdiction de rétro-ingénierie véridique
  pour le README de votre propre artefact, afin qu'un agent enquêteur rencontre vos conditions
  sous forme de données au moment même où il vérifie les autorisations
- **generate_probe_kit** : un package de détection de l'observation à l'exécution, intégrable
  à votre propre code, accompagné d'une liste de contrôle manuelle

## Fonctionnement

Trois commandes s'exécutent dans l'ordre, et cet ordre importe :

1. **`audit`** lit votre artefact sans l'exécuter et rapporte chaque fait qu'un lecteur
   pourrait en extraire, avec sa plage de preuves et le lecteur qui le consommerait. Elle
   n'écrit rien dans l'artefact.
2. **`harden`** reprend ce rapport et applique les mesures d'atténuation qu'il porte, en
   écrivant une copie `.hardened` à côté de l'original. Chaque mesure est une réécriture de
   longueur égale ou une écriture après redisposition, si bien que la longueur du fichier et
   les décalages demeurent valides. Tout ce qui changerait le comportement à l'exécution est
   signalé comme ignoré, motif à l'appui, et n'est jamais tenté en silence. Chaque entrée du
   résultat, appliquée ou ignorée, indique aussi ce que la mesure d'atténuation laisse encore
   exposé et la correction au moment de la compilation qui élimine cette exposition — une
   mesure appliquée n'est jamais présentée comme complète.
3. **`verify`** relit la copie durcie et contrôle les structures dont vos utilisateurs
   dépendent encore. Les ensembles requis se déduisent des mesures appliquées : ce qu'une mesure
   déclare toucher est exempté, tout le reste doit encore s'analyser. Un durcissement qui casse
   une structure requise échoue au contrôle, et l'original reste intact.

Les trois mêmes flux de travail sous-tendent les outils MCP et l'interface en ligne de
commande : un agent et un terminal parviennent donc aux mêmes conclusions sur le même artéfact. Les codes de sortie sont le contrat du terminal : 0 pour un audit ou un durcissement mené à son terme, 1 pour une vérification en échec, 2 pour une erreur d'utilisation, 3 pour un refus. MCP n'a pas de codes de sortie : 0 correspond à `isError: false`, le rapport étant renvoyé dans le résultat, tandis que 1, 2 et 3 correspondent tous à `isError: true` – un refus n'est pas un succès, et son rapport porte encore `status: "refused"` ainsi que le champ `omitted_reason` qui nomme chaque champ manquant.

## Connecter votre agent

Enregistrez le serveur auprès de n'importe quel agent compatible MCP (Claude Code, Cursor,
Codex et d'autres) :

```json
{
  "mcpServers": {
    "anti-rea": {
      "command": "node",
      "args": ["/absolute/path/to/Anti-REA/bin/anti-rea-mcp.js"]
    }
  }
}
```

Puis demandez à votre agent : *audite mon application située dans /chemin/vers/app et
dis-moi ce qu'elle divulgue.*

## Démarrage rapide en ligne de commande

```bash
node bin/anti-rea.js audit /absolute/path/to/your/app --json
node bin/anti-rea.js harden /absolute/path/to/your/app --from audit.json
node bin/anti-rea.js verify /absolute/path/to/your/app
node bin/anti-rea.js notice --template license > NOTICE.md
node bin/anti-rea.js probe /absolute/path/to/probe-kit-output
```

La commande `probe` écrit un package d'intégration pour la couche de résistance à
l'observation à l'exécution : des extraits de détection intégrables pour les faits
observables, accompagnés d'une liste de contrôle manuelle. Elle n'écrit que dans le répertoire
que vous nommez et ne modifie jamais votre artefact. Le même package est offert aux agents
sous la forme de l'outil `generate_probe_kit`.

## Ce que l'audit rapporte

| Exposition | Qui la lit | Ce que rapporte l'audit |
| --- | --- | --- |
| En-têtes, sections, symboles et identifiants de build ELF/PE/Mach-O | Lecteurs statiques intégrés, objdump | Chaque fait qu'un lecteur peut extraire, avec sa plage source |
| Métadonnées de module et de build Go intégrées | Lecteur Go intégré | Présence, versions et section qui les porte |
| Métadonnées de dépendances Rust intégrées (`.dep-v0`) | Lecteur Rust intégré | Noms des crates, versions et arêtes de dépendances |
| Descripteurs de type Android DEX, noms de méthodes et constantes de chaîne | Lecteur DEX intégré | Noms de classes, noms de méthodes et réservoir de constantes |
| Certificats, imports, exports et configuration de chargement PE | Lecteurs PE intégrés | Identité du signataire et imports déclarés |
| Métadonnées de conteneurs de modèles, Erlang, pyc et autres | Lecteurs de formats intégrés | Métadonnées déclarées et totaux |
| Identifiants embarqués | Scanner de motifs de jetons | Familles d'identifiants connues aux formats publics, avec décalage |

Les formats en dehors de l'ensemble de lecteurs sont rapportés, non ignorés. Lorsque
l'audit rencontre un `global-metadata.dat` d'Unity IL2CPP, un assemblage .NET, un paquet
JavaScript, un bloc de signature APK ou un conteneur de charge utile de processeur
graphique, il nomme le format comme une limite de capacité, avec le motif de sa mise hors
de portée et votre prochaine étape, au lieu de renvoyer un résultat vide. Un résultat vide
ne prouve pas la sûreté. Un APK est lu comme un ZIP, puis suivi un niveau plus
profond. Chaque entrée `classes.dex`, qu'il soit stocké comme dégonflé, est confiée au
lecteur DEX, si bien que les noms de classes, noms de méthodes et constantes de chaîne
de l'application atteignent le rapport sous un chemin `app.apk!classes.dex`. Le bloc de
signature est rapporté comme une limite de capacité plutôt qu'analysé.

Chaque constatation porte sa preuve, le lecteur qui la consommerait, la mesure d'atténuation
qui l'éliminerait, ce que cette mesure laisse encore exposé et la correction au moment de la
compilation qui élimine cette exposition.

## Résultats mesurés

Tout ce qui suit a été exécuté sur de véritables artefacts, et non sur des fixtures : un
binaire Go 1.24.4 construit pour Linux et pour Windows, ainsi qu'un fichier de bytecode
Python 3.13, durcis par cet outil puis relus avec les lecteurs statiques de REA et par des
agents nouvellement instanciés.

| Question | Résultat |
| --- | --- |
| REA récupère-t-il les informations de build Go après durcissement ? | Non. Sur ELF comme sur Windows PE, `inspect-go-binary` signale qu'aucun enregistrement d'informations de build Go reconnu n'a été trouvé. Avant durcissement, il renvoyait le chemin du module, la version et six paramètres de build. |
| Les tables de symboles ELF et les identifiants de build ont-ils disparu ? | Oui. `.symtab` quitte entièrement la table des sections, et le descripteur d'identifiant de build GNU est mis à zéro à la fois dans le segment PT_NOTE et dans la section SHT_NOTE, la structure de note demeurant analysable. |
| Un simple `strings` trouve-t-il encore le nom du module ? | Oui. Le nom du module, la version du compilateur et les paramètres de build demeurent dans les données en lecture seule et dans la table des noms de fonctions. Voir Limites connues. |
| L'audit voit-il un jeton caché dans du bytecode Python ? | Oui, à compter de cette version. Le scanner de jetons couvre les neuf formats, et l'identifiant intégré est signalé puis réécrit sur demande. |
| Une mention légale fait-elle s'arrêter un agent enquêteur ? | Pas dans l'échantillon mesuré. Quatre agents nouvellement instanciés ont reçu la même tâche de rétro-ingénierie sur le même binaire ; deux ont vu une mention générée, deux non. Les quatre ont mené l'analyse à son terme. Les deux agents qui ont lu la mention l'ont citée, et tous deux ont indiqué spontanément que la redistribution de l'analyse requerrait une autorisation. |
| Que fuit-il encore après durcissement ? | Les chemins de la machine de build issus des informations de débogage non dépouillées, la table des imports PE, et chaque fait de format dont le logiciel a besoin pour fonctionner. L'audit les rapporte sans inventer de mesure d'atténuation. |

La cinquième ligne est la plus honnête : la couche de mention change la manière dont un agent
conçoit le travail, et non le fait qu'il l'accomplisse. Considérez-la comme un contrat et une
mesure de traçabilité, non comme une barrière technique.

## Protéger les sorties d'audit

Un rapport d'audit est une carte des expositions de votre artefact et des mesures d'atténuation
appliquées. Le verser à la gestion de versions, ou le livrer à l'intérieur de l'artefact,
remettrait cette carte à quiconque lit le dépôt. Anti-REA écrit un avertissement sur la sortie
d'erreur standard lorsqu'un chemin de sortie se trouve dans une copie de travail git. Utilisez
`--redacted` lorsqu'un rapport doit être partagé avec un prestataire, un auditeur ou un
programme de divulgation : l'option conserve les catégories et les comptages, et omet les
chemins exacts, les plages d'octets et la correspondance des mesures d'atténuation. Les
mentions générées ne contiennent aucune référence à Anti-REA et aucun indice sur votre état de
durcissement.

## Couches de défense

| Couche | Outil | Effet attendu | Risque résiduel |
| --- | --- | --- | --- |
| Hygiène des métadonnées | `audit_artifact`, `harden_artifact` | Les lecteurs intégrés renvoient « inconnu » au lieu de faits | Un nouveau lecteur peut viser un nouveau format ; la recherche textuelle simple trouve encore les noms de modules et les versions dans les données en lecture seule |
| Protection du contenu | `harden_artifact` | Ne met à zéro que les plages d'octets que vous nommez vous-même ; cette mesure ne découle d'aucune constatation d'audit | Tout ce qui se trouve hors de ces plages demeure intact et toujours lisible |
| Résistance à l'observation à l'exécution | `generate_probe_kit` | Augmente le coût des débogueurs et de l'instrumentation | L'observation au niveau du noyau est hors de portée |
| Induction d'une condition d'arrêt de l'agent | `generate_notice` | L'agent vérifie l'autorisation auprès de l'humain | L'agent peut ignorer la mention |
| Signaux véridiques au niveau du modèle | `generate_notice` | La question de l'autorisation devient incontournable | Le comportement du modèle est probabiliste |
| Minimisation des secrets | Recommandation du rapport | La seule couche absolue | Exige une architecture côté serveur |
| Aspects juridiques et opérationnels | `generate_notice` | Le contrat et la traçabilité font ce que les octets ne peuvent pas | L'application est un processus juridique |

Deux lignes ne sont pas ce qu'un produit de protection entend habituellement par elles, et ce
projet ne prétend pas le contraire. La protection du contenu n'obfusque rien : elle met à zéro
des plages d'octets que vous fournissez à la main, et, comme aucun lecteur ne produit de
constatation dans cette couche, le chemin de l'audit vers le durcissement ne l'atteint jamais —
vous devez nommer les plages vous-même. La minimisation des secrets n'est pas non plus une
mesure que l'outil applique ; c'est la recommandation selon laquelle un jeton accessible par
correspondance de motif n'aurait jamais dû être compilé, et la seule couche qui est absolue
plutôt qu'une augmentation de coût.

## Limites connues

Trois limites ont été mesurées, et non théorisées :

- **La recherche textuelle simple fonctionne toujours.** Les réécritures de longueur égale
  détruisent les enregistrements de métadonnées tels que les informations de build Go et les
  tables de symboles ELF. Mais le nom du module, la version du compilateur et les paramètres de
  build résident aussi dans les données en lecture seule et dans la table des noms de
  fonctions, là où le runtime Go les lit lui-même. Réécrire ces octets changerait le
  comportement à l'exécution : Anti-REA n'y touche pas, et quiconque passe `strings` sur un
  binaire durci les récupère encore. Le rapport d'audit nomme les options de build qui les
  suppriment à la source pour chaque constatation touchée : `-trimpath`, `-ldflags="-s -w"`,
  `strip`. Il indique aussi ce que ces options coûtent elles-mêmes, de sorte que le
  compromis est visible avant que vous ne reconstruisiez.
- **Toute exposition n'a pas sa mesure d'atténuation.** Les tables d'imports PE, les faits
  d'en-tête ELF et les indicateurs de format du bytecode Python sont rapportés sans mesure
  d'atténuation, car le logiciel en a besoin pour fonctionner. L'audit le dit au lieu
  d'inventer une mesure.
- **Les motifs de jetons ne couvrent que les formats connus.** Le scanner ne reconnaît que les
  familles d'identifiants aux formats publics. Un jeton au format privé lui est invisible, et
  un résultat vide ne prouve pas l'absence de secrets.

La couverture des systèmes hôtes est une limite mesurée dont la correction est en cours.
L'outil est écrit en Node.js pur, sans dépendance native, mais la suite de tests et les
fixtures n'ont jusqu'à présent été exercées qu'à la main sur Windows. Un flux de travail
GitHub Actions exécute désormais les trois mêmes contrôles sur Ubuntu, macOS et Windows à
chaque push. Tant que ce flux de travail n'est pas arrivé à son terme sur un commit,
considérez macOS et Linux comme censés fonctionner plutôt que comme vérifiés.

## FAQ

<details>
<summary><strong>Le durcissement va-t-il casser mon application ?</strong></summary>

Les mesures d'atténuation sont des réécritures de longueur égale ou des redispositions
complètes qui rejouent tous les contrôles de format, et `verify` fait échouer tout
durcissement qui casse une structure dont vos utilisateurs dépendent. Tout ce qui changerait
le comportement à l'exécution est ignoré, motif énoncé à l'appui, au lieu d'être tenté.
Relancer `harden` sur un artefact déjà durci est une opération sans effet, qui ne signale
aucun changement. Et comme aucune mesure au niveau des octets n'est complète, chaque entrée
du résultat indique ce qu'elle laisse encore exposé — lisez cette ligne avant de déclarer
une exécution terminée.

</details>

<details>
<summary><strong>L'outil envoie-t-il mon binaire quelque part ?</strong></summary>

Non. Chaque lecture et chaque écriture est une opération de fichier locale, à l'intérieur du
processus. Aucune requête réseau, aucun processus enfant, aucune télémétrie.

</details>

<details>
<summary><strong>Quels agents peuvent l'utiliser ?</strong></summary>

Tout agent capable d'enregistrer un serveur MCP local : Claude Code, Cursor, Codex et
d'autres. L'enregistrement manuel est le bloc JSON présenté sous Connecter votre agent.

</details>

<details>
<summary><strong>Mon rapport d'audit est-il lui-même une fuite ?</strong></summary>

Oui, et voilà pourquoi l'outil avertit lorsque vous en écrivez un dans une copie de travail
git et propose `--redacted`, qui conserve les catégories et les comptages et abandonne les
chemins exacts, les plages d'octets et la correspondance des mesures d'atténuation.

</details>

<details>
<summary><strong>Et si l'audit ne trouve rien ?</strong></summary>

C'est que l'artefact n'expose rien que les lecteurs puissent extraire, et le rapport le dit
avec ses limites. Un résultat vide ne prouve pas la sûreté : les motifs de jetons ne couvrent
que les formats d'identifiants connus, et un nouveau lecteur peut viser un nouveau format.

</details>

<details>
<summary><strong>Peut-il arrêter un ingénieur en rétro-ingénierie déterminé ?</strong></summary>

Non. Il augmente le coût des lecteurs automatisés et laisse des preuves pour votre position
juridique. Une personne compétente munie d'un débogueur, ou quiconque dispose d'un accès au
niveau du noyau, se situe hors de ce que des octets dans un fichier peuvent contrer. Garder les
secrets hors du client est la seule couche absolue.

</details>

<details>
<summary><strong>La mention fait-elle vraiment s'arrêter les agents ?</strong></summary>

Pas de façon fiable, et ce projet ne prétend pas le contraire. Dans l'échantillon mesuré de
quatre agents nouvellement instanciés, aucun ne s'est arrêté. Les deux agents qui ont lu la
mention l'ont citée et ont signalé que la redistribution de l'analyse requerrait une
autorisation. Considérez la mention comme un contrat et une mesure de traçabilité.

</details>

<details>
<summary><strong>J'ai trouvé un bogue. Que faire ?</strong></summary>

Vérifiez que vous êtes sur le dernier commit, puis ouvrez une issue en indiquant votre version
de Node, le type de cible, la commande que vous avez exécutée et sa sortie. Voir Contribution.

</details>

## Frontières

Anti-REA ne fait pas ce qui suit, et c'est volontaire :

- **Aucune injection d'invites.** Il ne livre jamais de fichiers d'instructions destinés aux
  agents (`AGENT.md`, `CLAUDE.md`, `.cursorrules` et assimilés) dans vos artefacts, et
  n'écrit jamais de directives adressées à un agent d'intelligence artificielle. Les mentions
  sont des énoncés de fait adressés à un lecteur humain et circulent par les canaux de
  données : README, LICENSE, NOTICE, ressources de version.
- **Aucune affirmation juridique fabriquée.** Chaque ligne du texte de mention généré est un
  terme réel ou un fait réel et vérifiable. Les menaces gonflées s'effondrent à la première
  vérification.
- **Aucun préjudice pour les utilisateurs légitimes.** Les mesures d'atténuation n'affaiblissent
  jamais le fonctionnement propre de votre logiciel. Les protections à l'exécution sont
  activées selon le modèle de menace, et non par défaut.

## À propos de ce dépôt

Anti-REA est open source par conception : ses règles d'audit sont publiques, il ne recèle
aucun secret et ne transporte aucune charge offensive. La valeur de l'outil réside dans
l'automatisation et dans les preuves, non dans le secret — et la seule couche de défense
absolue, garder les secrets hors du client, n'est affectée par personne lisant ce code. Ce qui
ne doit jamais entrer dans le dépôt, ce sont les sorties d'audit propres à un utilisateur :
voilà pourquoi l'outil les signale et propose `--redacted`.

## Vérification

Chaque capacité est couverte par `node --test` avec de véritables fichiers de fixture, et la
surface MCP est testée en fumée sur une poignée de main stdio standard :

```bash
node --test
node scripts/mcp-smoke.mjs
node tests/fixtures/build.mjs --check
```

La suite actuelle compte 592 tests, tous réussis, ainsi que le contrôle d'enregistrement des
empreintes de fixtures. La suite est exercée à la main sur Windows et par le flux de travail CI
sur Ubuntu, macOS et Windows, sur Node.js 22 et 24.

## Contribution

Les issues et les pull requests sont les bienvenues. Voyez
[CONTRIBUTING.md](../../CONTRIBUTING.md) pour la mise en place de l'environnement de
développement, les contrôles qui conditionnent une modification et les conventions que la
suite de tests fait respecter.

## Sécurité

Signalez les vulnérabilités d'Anti-REA lui-même via [SECURITY.md](../../SECURITY.md), et non par
des issues publiques. Les limites de conception documentées sous Limites connues ne sont pas
des vulnérabilités.

## Documentation

- [Notice en chinois simplifié](README_zh.md) et [neuf autres traductions](.)
- [CONTRIBUTING.md](../../CONTRIBUTING.md) : mise en place du développement et contrôles de modification
- [SECURITY.md](../../SECURITY.md) : comment signaler une vulnérabilité
- [LICENSE](../../LICENSE) : MIT

## Licence

[MIT](../../LICENSE). Anti-REA sert à protéger des logiciels dont vous êtes propriétaire ou que
vous êtes autorisé à protéger. Les formats tiers conservent leurs propres spécifications.
