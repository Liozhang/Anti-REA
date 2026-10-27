<div align="center">

# Anti-REA

### Un server MCP per proteggere il proprio software dall'ingegneria inversa condotta da agenti

**Analizza cosa espongono i tuoi artefatti rilasciati. Applica le mitigazioni. Verifica il risultato.**

[![Licenza: MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](../../LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933.svg)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-5c4ee5.svg)](#collega-il-tuo-agente)
[![Test](https://img.shields.io/badge/tests-node--test-5c4ee5.svg)](#verifica)

**Italiano** · [English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Deutsch](README_de.md) · [Français](README_fr.md) · [Español](README_es.md) · [Português (Brasil)](README_pt-BR.md) · [Русский](README_ru.md)

Node.js senza dipendenze. Tutto viene eseguito in locale. Richiede Node.js 22 o una versione successiva.

[Come funziona](#come-funziona) · [Avvio rapido da terminale](#avvio-rapido-da-terminale) · [Cosa riporta l'audit](#cosa-riporta-laudit) · [Risultati misurati](#risultati-misurati) · [Livelli di difesa](#livelli-di-difesa) · [Limiti noti](#limiti-noti) · [Domande frequenti](#domande-frequenti) · [Verifica](#verifica) · [Contribuire](#contribuire) · [Sicurezza](#sicurezza)

</div>

---

> [!IMPORTANT]
> Scarica Anti-REA esclusivamente da questo repository. Non esiste ancora una
> release su npm, e un pacchetto dal nome simile non stabilisce che un download
> sia ufficiale. Usalo solo su software di tua proprietà o che sei autorizzato
> a proteggere.

REA (Reverse Engineer Anything) e catene di strumenti simili basate su MCP permettono a un agente
di intelligenza artificiale di ispezionare un binario, un pacchetto o un'applicazione rilasciati
senza il relativo codice sorgente, di spiegare come funziona una funzionalità e di costruirne una
versione. Questo porta il costo per comprendere il software che distribuisci vicino allo zero.

Anti-REA è la controparte per chi difende. È un server MCP, con un'interfaccia a riga di comando
che condivide gli stessi flussi di lavoro, che protegge **il tuo progetto** prima della
distribuzione:

- **audit_artifact**: ciò che un artefatto rilasciato espone ai lettori e ai motori che questi
  strumenti usano, con l'evidenza e l'intervallo di byte dietro ogni fatto
- **harden_artifact**: applica le mitigazioni che lo strumento può applicare e segnala quelle che
  richiedono strumenti esterni o una modifica architetturale
- **verify_artifact**: conferma che le mitigazioni reggono
- **generate_notice**: testo di licenza e di divieto di ingegneria inversa veritiero per il README
  del tuo artefatto, così che un agente intento a indagare incontri le tue condizioni come dati,
  nel momento in cui verifica l'autorizzazione
- **generate_probe_kit**: un pacchetto di rilevazione dell'osservazione a runtime integrabile nel
  tuo codice, più una checklist manuale

## Come funziona

Tre comandi vengono eseguiti in ordine, e l'ordine conta:

1. **`audit`** legge il tuo artefatto senza eseguirlo e riporta ogni fatto che un lettore
   potrebbe estrarre, ciascuno con il proprio intervallo di evidenza e il lettore che lo
   consumerebbe. Non scrive nulla nell'artefatto.
2. **`harden`** prende quel rapporto e applica le mitigazioni che può, scrivendo una copia
   `.hardened` accanto all'originale. Ogni mitigazione è una sovrascrittura di lunghezza uguale o
   una scrittura con riorganizzazione, quindi lunghezza del file e offset restano validi.
   Qualsiasi intervento che cambierebbe il comportamento a runtime viene segnalato come saltato,
   con il motivo, e non viene mai tentato in silenzio.
3. **`verify`** rilegge la copia protetta e controlla le strutture da cui i tuoi utenti dipendono
   ancora. Gli insiemi richiesti derivano dalle mitigazioni applicate: ciò che una mitigazione
   dichiara di toccare viene esentato, tutto il resto deve continuare a essere interpretabile.
   Un'esecuzione di protezione che rompe una struttura richiesta non supera la verifica, e
   l'originale resta intatto.

Gli stessi tre flussi di lavoro sostengono gli strumenti MCP e la CLI, quindi un agente e un
terminale ottengono risultati identici e codici di uscita identici: 0 per audit o protezione
completati, 1 per verifica non superata, 2 per errore di utilizzo, 3 per rifiuto.

## Collega il tuo agente

Registra il server con qualsiasi agente in grado di usare MCP (Claude Code, Cursor, Codex e
altri):

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

Poi chiedi al tuo agente: *analizza la mia app in /path/to/app e dimmi cosa espone.*

## Avvio rapido da terminale

```bash
node bin/anti-rea.js audit /absolute/path/to/your/app --json
node bin/anti-rea.js harden /absolute/path/to/your/app --from audit.json
node bin/anti-rea.js verify /absolute/path/to/your/app
node bin/anti-rea.js notice --template license > NOTICE.md
node bin/anti-rea.js probe /absolute/path/to/probe-kit-output
```

Il comando `probe` scrive un pacchetto di integrazione per il livello di resistenza
all'osservazione a runtime: snippet di rilevazione integrabili per fatti osservabili, più una
checklist manuale. Scrive solo nella directory che indichi e non modifica mai il tuo artefatto.
Lo stesso pacchetto è disponibile per gli agenti come strumento `generate_probe_kit`.

## Cosa riporta l'audit

| Esposizione | Chi la legge | Cosa riporta l'audit |
| --- | --- | --- |
| Intestazioni, sezioni, simboli e ID di build ELF/PE/Mach-O | Lettori statici integrati, objdump | Ogni fatto che un lettore può estrarre, con il proprio intervallo di origine |
| Metadati di modulo e build Go incorporati | Lettore Go integrato | Presenza, versioni e la sezione che li contiene |
| Metadati delle dipendenze Rust incorporati (`.dep-v0`) | Lettore Rust integrato | Nomi delle crate, versioni e archi di dipendenza |
| Metadati Unity IL2CPP | Lettore IL2CPP integrato | Nomi di tipi e metodi recuperabili |
| Metadati .NET e CIL | Lettore managed integrato | Fatti degli assembly e inventario dei membri |
| Source map e grafi dei moduli JavaScript | Lettore JavaScript integrato | Sorgenti originali recuperabili |
| Certificati, importazioni, esportazioni e configurazione di caricamento PE | Lettori PE integrati | Identità del firmatario e importazioni dichiarate |
| Metadati di contenitori per modelli, SQLite, Erlang, pyc e altri formati | Lettori di formato integrati | Metadati dichiarati e totali |
| Credenziali incorporate | Scanner di pattern per token | Famiglie di credenziali note con formati pubblici, con offset |

Ogni riscontro riporta la propria evidenza, il lettore che lo consumerebbe e la mitigazione che lo
elimina.

## Risultati misurati

Tutto ciò che segue è stato eseguito su artefatti reali, non su fixture: un binario Go 1.24.4
compilato per Linux e per Windows e un file di bytecode Python 3.13, protetti da questo
strumento e poi riletti con i lettori statici di REA e da agenti nuovi.

| Domanda | Risultato |
| --- | --- |
| REA recupera le informazioni di build Go dopo la protezione? | No. Sia su ELF sia su Windows PE, `inspect-go-binary` segnala che non è stato trovato alcun record di build-info Go riconosciuto. Prima della protezione restituiva il percorso del modulo, la versione e sei impostazioni di build. |
| Le tabelle dei simboli ELF e gli ID di build sono spariti? | Sì. `.symtab` esce del tutto dalla tabella delle sezioni, e il descrittore del build-ID GNU viene azzerato sia nel segmento PT_NOTE sia nella sezione SHT_NOTE, lasciando la struttura del note interpretabile. |
| Il semplice `strings` riesce ancora a trovare il nome del modulo? | Sì. Il nome del modulo, la versione del compilatore e le impostazioni di build restano nei dati di sola lettura e nella tabella dei nomi delle funzioni. Vedi Limiti noti. |
| L'audit vede un token nascosto nel bytecode Python? | Sì, a partire da questa release. Lo scanner di token opera su tutti gli otto formati, e la credenziale incorporata viene segnalata e sovrascritta su richiesta. |
| Un avviso legale ferma un agente che conduce un'indagine? | Non nel campione misurato. Quattro agenti nuovi hanno ricevuto lo stesso compito di ingegneria inversa sullo stesso binario; due hanno visto un avviso generato, due no. Tutti e quattro hanno completato l'analisi. Entrambi gli agenti che hanno letto l'avviso lo hanno citato, ed entrambi hanno fatto notare spontaneamente che ridistribuire l'analisi avrebbe richiesto un'autorizzazione. |
| Cosa continua a trapelare dopo la protezione? | I percorsi della macchina di build nelle informazioni di debug non rimosse, la tabella delle importazioni PE e ogni fatto di formato necessario al software per funzionare. L'audit riporta questi elementi senza inventare una mitigazione. |

La quinta riga è quella onesta: il livello dell'avviso cambia il modo in cui un agente inquadra il
lavoro, non se lo svolge. Trattalo come misura contrattuale e di tracciabilità, non come barriera
tecnica.

## Proteggi gli output dell'audit

Un rapporto di audit è una mappa delle esposizioni del tuo artefatto e delle mitigazioni
applicate. Salvarlo nel controllo di versione, o distribuirlo all'interno dell'artefatto,
consegna quella mappa a chiunque legga il repository. Anti-REA scrive un'avvertenza sullo
standard error quando un percorso di output si trova in un working tree git. Usa `--redacted`
quando un rapporto deve essere condiviso con un contraente, un revisore o un programma di
divulgazione: conserva categorie e conteggi ed omette percorsi esatti, intervalli di byte e la
corrispondenza delle mitigazioni. Gli avvisi generati non contengono riferimenti ad Anti-REA né
indizi sul tuo stato di protezione.

## Livelli di difesa

| Livello | Strumento | Effetto atteso | Rischio residuo |
| --- | --- | --- | --- |
| Igiene dei metadati | `audit_artifact`, `harden_artifact` | I lettori integrati restituiscono sconosciuto invece dei fatti | Un nuovo lettore può prendere di mira un nuovo formato; la ricerca testuale semplice trova ancora nomi di modulo e versioni nei dati di sola lettura |
| Protezione del contenuto | Indicazioni di `harden_artifact` | La decompilazione statica vede stub, non il programma | Il dump a runtime recupera il codice spacchettato |
| Resistenza all'osservazione a runtime | `generate_probe_kit` | Alza il costo di debugger e strumentazione | L'osservazione a livello di kernel è fuori portata |
| Induzione della condizione di arresto dell'agente | `generate_notice` | L'agente verifica l'autorizzazione con l'essere umano | L'agente può ignorare l'avviso |
| Segnali veritieri a livello di modello | `generate_notice` | La domanda sull'autorizzazione diventa inevitabile | Il comportamento del modello è probabilistico |
| Minimizzazione dei segreti | Raccomandazione del rapporto | L'unico livello assoluto | Richiede un'architettura lato server |
| Legale e operativo | `generate_notice` | Contratto e tracciabilità fanno ciò che i byte non possono | L'applicazione è un processo legale |

## Limiti noti

Tre limiti sono stati misurati, non teorizzati:

- **La ricerca testuale semplice funziona ancora.** Le sovrascritture di lunghezza uguale
  distruggono i record di metadati come le informazioni di build Go e le tabelle dei simboli ELF,
  ma il nome del modulo, la versione del compilatore e le impostazioni di build vivono anche nei
  dati di sola lettura e nella tabella dei nomi delle funzioni, dove il runtime Go li legge.
  Sovrascrivere quei byte cambia il comportamento a runtime, quindi Anti-REA li lascia stare, e
  chiunque esegua `strings` su un binario protetto li recupera ancora. Rimuovili all'origine con
  le flag di build (`-trimpath`, `-ldflags="-s -w"`, `strip`).
- **Non ogni esposizione ha una mitigazione.** Le tabelle delle importazioni PE, i fatti delle
  intestazioni ELF e i flag di formato del bytecode Python vengono riportati senza mitigazione,
  perché il software ne ha bisogno per funzionare. L'audit lo dice invece di inventare una misura.
- **I pattern dei token coprono solo i formati noti.** Lo scanner riconosce le famiglie di
  credenziali con formati pubblici. Un token in un formato privato è invisibile allo scanner, e
  un risultato vuoto non prova che non esistano segreti.

Anche la copertura delle piattaforme è un limite misurato: lo strumento è Node.js puro senza
dipendenze native, ma la suite di test e le fixture sono state esercitate solo su Windows. macOS
e Linux dovrebbero funzionare e non sono ancora verificati.

## Domande frequenti

<details>
<summary><strong>La protezione romperà la mia applicazione?</strong></summary>

Le mitigazioni sono sovrascritture di lunghezza uguale o riorganizzazioni complete che
rieseguono ogni controllo di formato, e `verify` boccia un'esecuzione che rompe una struttura da
cui dipendono i tuoi utenti. Qualsiasi intervento che cambierebbe il comportamento a runtime
viene saltato con un motivo dichiarato anziché tentato. Rieseguire `harden` su un artefatto già
protetto è un'operazione senza effetto che non riporta alcun cambiamento.

</details>

<details>
<summary><strong>Lo strumento carica il mio binario da qualche parte?</strong></summary>

No. Ogni lettura e scrittura è un'operazione su file locale dentro il processo. Nessuna richiesta
di rete, nessun processo figlio, nessuna telemetria.

</details>

<details>
<summary><strong>Quali agenti possono usarlo?</strong></summary>

Qualsiasi agente in grado di registrare un server MCP locale: Claude Code, Cursor, Codex e
altri. La registrazione manuale è il blocco JSON in Collega il tuo agente.

</details>

<details>
<summary><strong>Il mio rapporto di audit è esso stesso una falla?</strong></summary>

Sì, ed è per questo che lo strumento avvisa quando ne scrivi uno in un working tree git e offre
`--redacted`, che conserva categorie e conteggi ed elimina percorsi esatti, intervalli di byte e
la corrispondenza delle mitigazioni.

</details>

<details>
<summary><strong>E se l'audit non trova nulla?</strong></summary>

Allora l'artefatto non espone nulla che i lettori possano estrarre, e il rapporto lo dice con i
propri limiti. Un risultato vuoto non è una prova di sicurezza: i pattern dei token coprono solo
i formati di credenziali noti, e un nuovo lettore può prendere di mira un nuovo formato.

</details>

<details>
<summary><strong>Può fermare un reverse engineer determinato?</strong></summary>

No. Alza il costo dei lettori automatizzati e lascia evidenze per la tua posizione legale. Una
persona esperta con un debugger, o chiunque abbia accesso a livello di kernel, è fuori da ciò a
cui i byte di un file possono resistere. Tenere i segreti fuori dal client è l'unico livello
assoluto.

</details>

<details>
<summary><strong>L'avviso ferma davvero gli agenti?</strong></summary>

Non in modo affidabile, e questo progetto non afferma il contrario. Nel campione misurato di
quattro agenti nuovi, nessuno si è fermato. Entrambi gli agenti che hanno letto l'avviso lo hanno
citato e hanno segnalato che ridistribuire l'analisi avrebbe richiesto un'autorizzazione. Tratta
l'avviso come misura contrattuale e di tracciabilità.

</details>

<details>
<summary><strong>Ho trovato un bug. E adesso?</strong></summary>

Verifica di essere sull'ultimo commit, poi apri una issue con la tua versione di Node, il tipo di
target, il comando eseguito e l'output. Vedi Contribuire.

</details>

## Confini

Anti-REA non fa quanto segue, per progetto:

- **Nessuna iniezione di prompt.** Non inserisce mai file di istruzioni per agenti (`AGENT.md`,
  `CLAUDE.md`, `.cursorrules` e simili) nei tuoi artefatti e non scrive mai direttive rivolte a un
  agente di intelligenza artificiale. Gli avvisi sono dichiarazioni di fatto rivolte a un lettore
  umano e viaggiano attraverso canali di dati: README, LICENSE, NOTICE, risorse di versione.
- **Nessuna affermazione legale fabbricata.** Ogni riga del testo di avviso generato è un termine
  reale o un fatto reale e verificabile. Le minacce gonfiate crollano alla prima verifica.
- **Nessun danno agli utenti legittimi.** Le mitigazioni non indeboliscono mai il funzionamento
  del tuo software. Le protezioni a runtime sono opzionali, per modello di minaccia, e non sono
  attive per impostazione predefinita.

## Informazioni sul repository

Anti-REA è open source per progetto: le sue regole di audit sono pubbliche, non contiene segreti
e non trasporta payload di attacco. Il valore dello strumento è l'automazione e l'evidenza, non
la segretezza, e l'unico livello di difesa assoluto, tenere i segreti fuori dal client, non è
scalfito da chiunque legga questo codice. Ciò che non deve mai entrare nel repository è l'output
di audit specifico di un utente, ed è per questo che lo strumento lo segnala e offre `--redacted`.

## Verifica

Ogni funzionalità è coperta da `node --test` con file fixture reali, e la superficie MCP è
sottoposta a smoke test tramite un handshake stdio standard:

```bash
node --test
node scripts/mcp-smoke.mjs
node tests/fixtures/build.mjs --check
```

La suite attuale è di 526 test, tutti superati, più il controllo di registrazione dei digest
delle fixture. La suite viene eseguita su Windows con Node.js 22 e 24; le piattaforme macOS e
Linux non sono ancora state esercitate.

## Contribuire

Issue e pull request sono benvenute. Consulta [CONTRIBUTING.md](../../CONTRIBUTING.md) per la
configurazione dell'ambiente di sviluppo, i controlli che presidiano una modifica e le
convenzioni fatte rispettare dalla suite di test.

## Sicurezza

Segnala le vulnerabilità di Anti-REA stesso tramite [SECURITY.md](../../SECURITY.md), non in issue
pubbliche. I limiti di progetto documentati in Limiti noti non sono vulnerabilità.

## Documentazione

- [简体中文说明](README_zh.md) e [altre nove traduzioni](.)
- [CONTRIBUTING.md](../../CONTRIBUTING.md): configurazione dell'ambiente di sviluppo e controlli per le modifiche
- [SECURITY.md](../../SECURITY.md): come segnalare una vulnerabilità
- [LICENSE](../../LICENSE): MIT

## Licenza

[MIT](../../LICENSE). Anti-REA serve a proteggere software di tua proprietà o che sei autorizzato a
proteggere. I formati di terze parti mantengono le proprie specifiche.
