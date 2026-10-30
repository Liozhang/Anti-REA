<div align="center">

# Anti-REA

### Ein MCP-Server zur Härtung eigener Software gegen agentengetriebenes Reverse Engineering

**Prüfe, was deine ausgelieferten Artefakte offenlegen. Wende die Maßnahmen an. Verifiziere das Ergebnis.**

[![Lizenz: MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](../../LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933.svg)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-5c4ee5.svg)](#agenten-anbinden)
[![Tests](https://img.shields.io/badge/tests-node--test-5c4ee5.svg)](#verifikation)

[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · **Deutsch** · [Français](README_fr.md) · [Español](README_es.md) · [Português (Brasil)](README_pt-BR.md) · [Русский](README_ru.md) · [Italiano](README_it.md)

Node.js ohne Abhängigkeiten. Alles läuft lokal. Erfordert Node.js 22 oder neuer.

[Funktionsweise](#funktionsweise) · [Schnellstart im Terminal](#schnellstart-im-terminal) · [Was der Audit berichtet](#was-der-audit-berichtet) · [Gemessene Ergebnisse](#gemessene-ergebnisse) · [Verteidigungsebenen](#verteidigungsebenen) · [Bekannte Grenzen](#bekannte-grenzen) · [FAQ](#faq) · [Verifikation](#verifikation) · [Mitwirken](#mitwirken) · [Sicherheit](#sicherheit)

</div>

---

> [!IMPORTANT]
> Beziehe Anti-REA ausschließlich aus diesem Repository. Es gibt noch keine
> Veröffentlichung auf npm, und ein ähnlich benanntes Paket ist kein Beleg
> dafür, dass ein Download offiziell ist. Setze das Werkzeug nur bei Software
> ein, die dir gehört oder zu deren Schutz du autorisiert bist.

REA (Reverse Engineer Anything) und vergleichbare MCP-basierte Werkzeugketten ermöglichen es
einem KI-Agenten, ein ausgeliefertes Binary, ein Paket oder eine Anwendung ohne deren Quellcode
zu untersuchen, die Funktionsweise eines Merkmals zu erklären und eine eigene Version davon zu
erstellen. Damit sinken die Kosten, deine ausgelieferte Software zu verstehen, nahezu auf null.

Anti-REA ist das Gegenstück für die verteidigende Seite. Es ist ein MCP-Server – mit einer
Kommandozeilenschnittstelle, die dieselben Workflows nutzt – und härtet **dein eigenes Projekt**,
bevor es ausgeliefert wird:

- **audit_artifact**: was ein ausgeliefertes Artefakt den Lesern und Engines solcher Werkzeuge
  offenlegt, mit Beleg und Quellbereich hinter jedem Fakt
- **harden_artifact**: die Maßnahmen anwenden, die das Werkzeug umsetzen kann, und diejenigen
  melden, die externe Werkzeuge oder eine architektonische Änderung erfordern
- **verify_artifact**: bestätigen, dass die Maßnahmen greifen
- **generate_notice**: wahrheitsgemäße Lizenz- und No-Reverse-Engineering-Texte für das eigene
  README des Artefakts, damit ein untersuchender KI-Agent deine Bedingungen in dem Moment als
  Daten vorfindet, in dem er die Autorisierung prüft
- **generate_probe_kit**: ein einbettbares Erkennungspaket für Laufzeitbeobachtung im eigenen
  Code, plus eine manuelle Checkliste

## Funktionsweise

Drei Befehle laufen in fester Reihenfolge ab, und die Reihenfolge ist wichtig:

1. **`audit`** liest dein Artefakt, ohne es auszuführen, und meldet jedes Fakt, das ein Leser
   extrahieren könnte, jeweils mit seinem Belegbereich und dem Leser, der es verwerten würde. In
   das Artefakt wird nichts geschrieben.
2. **`harden`** übernimmt diesen Bericht und wendet die Maßnahmen an, die möglich sind, und
   schreibt eine `.hardened`-Kopie neben das Original. Jede Maßnahme ist ein Überschreiben mit
   gleicher Länge oder ein Schreibvorgang mit geändertem Layout, damit Dateilänge und Offsets
   gültig bleiben. Alles, was das Laufzeitverhalten ändern würde, wird mit Begründung als
   übersprungen gemeldet und niemals stillschweigend versucht. Jeder Eintrag im Ergebnis, ob
   angewandt oder übersprungen, nennt außerdem das Restrisiko der Maßnahme und die
   Build-Zeit-Korrektur, die es vollständig beseitigt – eine angewandte Maßnahme wird niemals
   als vollständig gemeldet.
3. **`verify`** liest die gehärtete Kopie erneut und prüft die Strukturen, auf die deine Nutzer
   weiterhin angewiesen sind. Die erforderlichen Mengen ergeben sich aus den angewandten
   Maßnahmen: Was eine Maßnahme als berührt deklariert, ist ausgenommen, alles andere muss sich
   weiterhin parsen lassen. Ein Härtungslauf, der eine erforderliche Struktur bricht, fällt durch
   die Prüfung, und das Original bleibt unberührt.

Dieselben drei Workflows liegen den MCP-Werkzeugen und der Kommandozeilenschnittstelle zugrunde.
Ein Agent und ein Terminal kommen damit bei demselben Artefakt zum selben Urteil. Die Exit-Codes sind der Vertrag des Terminals: 0 für einen abgeschlossenen Audit- oder Härtungslauf, 1 für eine fehlgeschlagene Verifikation, 2 für einen Anwendungsfehler, 3 für eine Ablehnung. MCP kennt keine Exit-Codes: 0 wird auf `isError: false` abgebildet, mit dem Bericht im Ergebnis, während 1, 2 und 3 alle auf `isError: true` abgebildet werden – eine Ablehnung ist kein Erfolg, und ihr Bericht trägt weiterhin `status: "refused"` sowie das `omitted_reason`, das jedes fehlende Feld benennt.

## Agenten anbinden

Registriere den Server bei jedem MCP-fähigen Agenten (Claude Code, Cursor, Codex und andere):

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

Frage deinen Agenten anschließend: *auditiere meine App unter /path/to/app und sag mir, was sie
offenlegt.*

## Schnellstart im Terminal

```bash
node bin/anti-rea.js audit /absolute/path/to/your/app --json
node bin/anti-rea.js harden /absolute/path/to/your/app --from audit.json
node bin/anti-rea.js verify /absolute/path/to/your/app
node bin/anti-rea.js notice --template license > NOTICE.md
node bin/anti-rea.js probe /absolute/path/to/probe-kit-output
```

Der Befehl `probe` schreibt ein Integrationspaket für die Ebene der Widerstandsfähigkeit gegen
Laufzeitbeobachtung: einbettbare Erkennungsfragmente für beobachtbare Fakten, plus eine manuelle
Checkliste. Er schreibt nur in das von dir benannte Verzeichnis und verändert dein Artefakt nie.
Dasselbe Paket steht Agenten als Werkzeug `generate_probe_kit` zur Verfügung.

## Was der Audit berichtet

| Offenlegung | Wer sie liest | Was der Audit berichtet |
| --- | --- | --- |
| ELF/PE/Mach-O-Header, Sektionen, Symbole und Build-IDs | Integrierte statische Leser, objdump | Jedes Fakt, das ein Leser extrahieren kann, mit seinem Quellbereich |
| Eingebettete Go-Modul- und Build-Metadaten | Integrierter Go-Leser | Vorhandensein, Versionen und die Sektion, die sie trägt |
| Eingebettete Rust-Abhängigkeitsmetadaten (`.dep-v0`) | Integrierter Rust-Leser | Crate-Namen, Versionen und Abhängigkeitskanten |
| Android-DEX-Typdeskriptoren, Methodennamen und Zeichenkettenkonstanten | Integrierter DEX-Leser | Klassennamen, Methodennamen und der Konstantenpool |
| PE-Zertifikate, Imports, Exports und Load Config | Integrierte PE-Leser | Identität des Signierers und deklarierte Imports |
| Modell-, Erlang-, pyc- und andere Container-Metadaten | Integrierte Format-Leser | Deklarierte Metadaten und Summen |
| Eingebettete Zugangsdaten | Token-Muster-Scanner | Bekannte Zugangsdaten-Familien mit öffentlichen Formaten, mit Offset |

Formate außerhalb des Leser-Satzes werden gemeldet, nicht übersprungen. Wenn der Audit
auf eine Unity-IL2CPP-`global-metadata.dat`, eine .NET-Assembly, ein JavaScript-Bundle,
einen APK-Signaturblock oder einen GPU-Payload-Container trifft, benennt er das Format
als Fähigkeitsgrenze, mit dem Grund, warum es außerhalb des Geltungsbereichs liegt,
und mit deinem nächsten Schritt, statt ein leeres Ergebnis zu liefern. Ein leeres
Ergebnis ist kein Beweis für Sicherheit. Ein APK wird als ZIP gelesen und dann eine Ebene
tiefer verfolgt. Jeder `classes.dex`-Eintrag, sowohl gespeicherte als auch deflatierte, wird
an den DEX-Leser übergeben, sodass die Klassennamen, Methodennamen und
Zeichenkettenkonstanten der App unter einem `app.apk!classes.dex`-Pfad in den Bericht
gelangen. Der Signaturblock wird als Grenze gemeldet und nicht geparst.

Jeder Befund trägt seinen Beleg, den Leser, der ihn verwerten würde, die Maßnahme, die ihn
beseitigen würde, das Restrisiko dieser Maßnahme und die Build-Zeit-Korrektur, die es
vollständig beseitigt.

## Gemessene Ergebnisse

Alles Folgende wurde auf echten Artefakten ausgeführt, nicht auf Fixtures: ein Go-1.24.4-Binary,
gebaut für Linux und für Windows, und eine Python-3.13-Bytecode-Datei, mit diesem Werkzeug
gehärtet und danach mit REAs eigenen statischen Lesern und von frischen Agenten zurückgelesen.

| Frage | Ergebnis |
| --- | --- |
| Stellt REA nach der Härtung Go-Build-Informationen wieder her? | Nein. Sowohl unter ELF als auch unter Windows PE meldet `inspect-go-binary`, dass kein erkannter Go-Build-Info-Datensatz gefunden wurde. Vor der Härtung gab es Modulpfad, Version und sechs Build-Einstellungen zurück. |
| Sind ELF-Symboltabellen und Build-IDs entfernt? | Ja. `.symtab` verschwindet vollständig aus der Sektionstabelle, und der GNU-Build-ID-Deskriptor wird sowohl im PT_NOTE-Segment als auch in der SHT_NOTE-Sektion genullt, wobei die Note-Struktur parsebar bleibt. |
| Findet einfaches `strings` weiterhin den Modulnamen? | Ja. Modulname, Compiler-Version und Build-Einstellungen bleiben in den Read-only-Daten und der Funktionsnamentabelle erhalten. Siehe Bekannte Grenzen. |
| Sieht der Audit ein in Python-Bytecode verstecktes Token? | Ja, ab dieser Version. Der Token-Scanner läuft über alle neun Formate, und die eingebetteten Zugangsdaten werden gemeldet und auf Anfrage überschrieben. |
| Bewirkt ein rechtlicher Hinweis, dass ein untersuchender Agent aufhört? | In der gemessenen Stichprobe nicht. Vier frische Agenten erhielten dieselbe Reverse-Engineering-Aufgabe an demselben Binary; zwei sahen einen generierten Hinweis, zwei nicht. Alle vier schlossen die Analyse ab. Beide Agenten, die den Hinweis lasen, zitierten ihn, und beide merkten von sich aus an, dass eine Weiterverbreitung der Analyse einer Autorisierung bedürfte. |
| Was wird nach der Härtung weiterhin offengelegt? | Build-Maschinen-Pfade aus nicht gestrippten Debug-Informationen, die PE-Importtabelle und jedes Formatfakt, das die Software zum Laufen braucht. Der Audit meldet diese, ohne eine Maßnahme zu erfinden. |

Die fünfte Zeile ist die ehrliche: Die Hinweisebene ändert, wie ein Agent die Arbeit einordnet,
nicht ob er sie tut. Betrachte sie als Vertrags- und Nachvollziehbarkeitsmaßnahme, nicht als
technische Barriere.

## Schütze deine Audit-Ausgaben

Ein Audit-Bericht ist eine Karte der Offenlegungen deines Artefakts und der angewandten
Maßnahmen. Ihn in die Versionsverwaltung zu committen oder im Artefakt mitzuliefern, übergibt
diese Karte jedem, der das Repository liest. Anti-REA schreibt eine Warnung auf die
Standardfehlerausgabe, wenn ein Ausgabepfad innerhalb eines Git-Arbeitsverzeichnisses liegt.
Verwende `--redacted`, wenn ein Bericht mit einem Auftragnehmer, einem Prüfer oder einem
Disclosure-Programm geteilt werden muss: Er behält Kategorien und Anzahlen und lässt exakte
Pfade, Byte-Bereiche und die Maßnahmen-Zuordnung weg. Generierte Hinweise enthalten keinen Verweis
auf Anti-REA und keinen Aufschluss über deinen Härtungszustand.

## Verteidigungsebenen

| Ebene | Werkzeug | Erwartete Wirkung | Restrisiko |
| --- | --- | --- | --- |
| Metadaten-Hygiene | `audit_artifact`, `harden_artifact` | Integrierte Leser geben unbekannt zurück statt Fakten | Ein neuer Leser kann ein neues Format anvisieren; einfache String-Suche findet weiterhin Modulnamen und Versionen in den Read-only-Daten |
| Inhaltsschutz | `harden_artifact` | Überschreibt nur die Bytebereiche, die du selbst benennst; kein Audit-Befund leitet diese Maßnahme ab | Alles außerhalb dieser Bereiche bleibt unberührt und weiterhin lesbar |
| Widerstand gegen Laufzeitbeobachtung | `generate_probe_kit` | Erhöht die Kosten für Debugger und Instrumentierung | Beobachtung auf Kernel-Ebene ist außer Reichweite |
| Induktion von Abbruchbedingungen beim Agenten | `generate_notice` | Der Agent klärt die Autorisierung mit dem Menschen | Der Agent kann den Hinweis ignorieren |
| Wahrheitsgemäße Signale auf Modellebene | `generate_notice` | Die Autorisierungsfrage wird unvermeidbar | Modellverhalten ist probabilistisch |
| Geheimnis-Minimierung | Empfehlung im Bericht | Die einzige absolute Ebene | Erfordert eine serverseitige Architektur |
| Rechtlich und operativ | `generate_notice` | Vertrag und Nachvollziehbarkeit schaffen, was Bytes nicht können | Durchsetzung ist ein Rechtsweg |

Zwei Zeilen sind nicht das, was ein Schutzprodukt üblicherweise darunter versteht, und
dieses Projekt behauptet das auch nicht. Inhaltsschutz verschleiert nichts: Er nullt
Bytebereiche, die du von Hand angibst, und weil in dieser Ebene kein Leser einen Befund
liefert, erreicht der Pfad vom Audit zur Härtung sie nie – du musst die Bereiche selbst
benennen. Geheimnis-Minimierung ist ebenfalls keine Maßnahme, die das Werkzeug anwendet;
sie ist die Empfehlung, dass ein Token, das durch einen Musterabgleich erreichbar ist,
niemals hätte kompiliert werden dürfen, und die einzige Ebene, die absolut ist statt
einer Kostensteigerung.

## Bekannte Grenzen

Drei Grenzen wurden gemessen, nicht theoretisch hergeleitet:

- **Einfache String-Suche funktioniert weiterhin.** Überschreiben mit gleicher Länge zerstört
  Metadaten-Datensätze wie Go-Build-Informationen und ELF-Symboltabellen. Aber Modulname,
  Compiler-Version und Build-Einstellungen liegen ebenfalls in den Read-only-Daten und der
  Funktionsnamentabelle, wo die Go-Laufzeit sie liest. Diese Bytes zu überschreiben ändert das
  Laufzeitverhalten, deshalb lässt Anti-REA sie unberührt, und alles, was `strings` über ein
  gehärtetes Binary laufen lässt, holt sie weiterhin heraus. Der Audit-Bericht nennt für
  jeden betroffenen Befund die Build-Flags, die sie an der Quelle entfernen: `-trimpath`,
  `-ldflags="-s -w"`, `strip`. Er nennt auch, was diese Flags selbst kosten, damit die
  Abwägung sichtbar ist, bevor du neu baust.
- **Nicht jede Offenlegung hat eine Maßnahme.** PE-Importtabellen, ELF-Header-Fakten und
  Python-Bytecode-Format-Flags werden ohne Maßnahme gemeldet, weil die Software sie zum Laufen
  braucht. Der Audit sagt das, statt eine Maßnahme zu erfinden.
- **Token-Muster decken nur bekannte Formate ab.** Der Scanner matcht Zugangsdaten-Familien mit
  öffentlichen Formaten. Ein Token in einem privaten Format ist für ihn unsichtbar, und ein
  leeres Ergebnis ist kein Beweis, dass keine Geheimnisse existieren.

Die Host-Abdeckung ist eine gemessene Grenze, deren Behebung in Arbeit ist. Das Werkzeug
ist reines Node.js ohne native Abhängigkeiten, aber die Testsuite und die Fixtures wurden
bisher nur unter Windows von Hand ausgeführt. Ein GitHub Actions Workflow führt nun bei
jedem Push dieselben drei Prüfungen auf Ubuntu, macOS und Windows aus. Bis dieser Workflow
auf einem Commit abgeschlossen ist, behandle macOS und Linux als voraussichtlich
funktionierend, nicht als verifiziert.

## FAQ

<details>
<summary><strong>Zerstört die Härtung meine Anwendung?</strong></summary>

Maßnahmen sind Überschreiben mit gleicher Länge oder vollständige Umbauten, bei denen jede
Formatprüfung erneut läuft, und `verify` lässt einen Lauf durchfallen, der eine Struktur bricht,
auf die deine Nutzer angewiesen sind. Alles, was das Laufzeitverhalten ändern würde, wird mit
angegebener Begründung übersprungen statt versucht. Ein erneutes `harden` auf einem bereits
gehärteten Artefakt ist ein No-op, das keine Änderung meldet. Und weil keine Maßnahme auf
Byte-Ebene vollständig ist, nennt jeder Eintrag im Ergebnis sein Restrisiko – lies diese
Zeile, bevor du einen Lauf als abgeschlossen betrachtest.

</details>

<details>
<summary><strong>Lädt das Werkzeug mein Binary irgendwohin hoch?</strong></summary>

Nein. Jedes Lesen und Schreiben ist eine lokale Dateioperation innerhalb des Prozesses. Keine
Netzwerkanfragen, keine Kindprozesse, keine Telemetrie.

</details>

<details>
<summary><strong>Welche Agenten können es nutzen?</strong></summary>

Jeder Agent, der einen lokalen MCP-Server registrieren kann: Claude Code, Cursor, Codex und
andere. Die manuelle Registrierung ist der JSON-Block unter Agenten anbinden.

</details>

<details>
<summary><strong>Ist mein Audit-Bericht selbst ein Leck?</strong></summary>

Ja, und deshalb warnt das Werkzeug, wenn du einen in ein Git-Arbeitsverzeichnis schreibst, und
bietet `--redacted` an, das Kategorien und Anzahlen behält und exakte Pfade, Byte-Bereiche und
die Maßnahmen-Zuordnung fallen lässt.

</details>

<details>
<summary><strong>Was, wenn der Audit nichts findet?</strong></summary>

Dann legt das Artefakt nichts offen, was die Leser extrahieren können, und der Bericht sagt das
mitsamt seinen Grenzen. Ein leeres Ergebnis ist kein Sicherheitsbeweis: Die Token-Muster decken
nur bekannte Zugangsdaten-Formate ab, und ein neuer Leser kann ein neues Format anvisieren.

</details>

<details>
<summary><strong>Kann es einen entschlossenen Reverse Engineer stoppen?</strong></summary>

Nein. Es erhöht die Kosten automatisierter Leser und hinterlässt Beweise für deine Rechtsposition.
Eine geübte Person mit einem Debugger und jeder mit Kernel-Zugriff liegen außerhalb dessen, was
Bytes in einer Datei widerstehen können. Geheimnisse vom Client fernzuhalten ist die einzige
absolute Ebene.

</details>

<details>
<summary><strong>Bringt der Hinweis Agenten wirklich zum Aufhören?</strong></summary>

Nicht verlässlich, und dieses Projekt behauptet das auch nicht. In der gemessenen Stichprobe von
vier frischen Agenten hielt keiner an. Beide Agenten, die den Hinweis lasen, zitierten ihn und
wiesen darauf hin, dass eine Weiterverbreitung der Analyse einer Autorisierung bedürfte.
Betrachte den Hinweis als Vertrags- und Nachvollziehbarkeitsmaßnahme.

</details>

<details>
<summary><strong>Ich habe einen Bug gefunden. Was nun?</strong></summary>

Prüfe, ob du auf dem neuesten Commit bist, und öffne dann ein Issue mit deiner Node-Version, dem
Zieltyp, dem ausgeführten Befehl und der Ausgabe. Siehe Mitwirken.

</details>

## Abgrenzung

Anti-REA tut folgende Dinge grundsätzlich nicht:

- **Keine Prompt-Injection.** Es liefert niemals Agenten-Anweisungsdateien (`AGENT.md`,
  `CLAUDE.md`, `.cursorrules` und ähnliche) in deinen Artefakten aus und schreibt niemals
  Direktiven an einen KI-Agenten. Hinweise sind sachliche Feststellungen an einen menschlichen
  Leser und reisen über Datenkanäle: README, LICENSE, NOTICE, Versionsressourcen.
- **Keine erfundenen Rechtsbehauptungen.** Jede Zeile eines generierten Hinweistexts ist eine
  echte Bedingung oder eine echte, überprüfbare Tatsache. Aufgeblähte Drohungen fallen beim
  ersten Nachprüfen in sich zusammen.
- **Kein Schaden für legitime Nutzer.** Maßnahmen schwächen nie den Betrieb deiner eigenen
  Software. Laufzeitschutz ist pro Bedrohungsmodell opt-in, nicht Standard.

## Über dieses Repository

Anti-REA ist grundsätzlich Open Source: Seine Audit-Regeln sind öffentlich, es enthält keine
Geheimnisse und trägt keine Angriffs-Payloads. Der Wert des Werkzeugs ist Automatisierung und
Beweiskraft, nicht Geheimhaltung – und die eine absolute Verteidigungsebene, Geheimnisse vom
Client fernzuhalten, bleibt davon unberührt, dass jedermann diesen Code liest. Was niemals in das
Repository gelangen darf, sind nutzerspezifische Audit-Ausgaben, weshalb das Werkzeug davor warnt
und `--redacted` anbietet.

## Verifikation

Jede Fähigkeit ist durch `node --test` mit echten Fixture-Dateien abgedeckt, und die
MCP-Oberfläche wird mit einem Smoke-Test über einen Standard-stdio-Handshake geprüft:

```bash
node --test
node scripts/mcp-smoke.mjs
node tests/fixtures/build.mjs --check
```

Die aktuelle Suite umfasst 595 Tests, alle bestehend, plus die Registrierungsprüfung der
Fixture-Digests. Die Suite wird unter Windows von Hand und auf Ubuntu, macOS und Windows
durch den CI-Workflow ausgeführt, auf Node.js 22 und 24.

## Mitwirken

Issues und Pull Requests sind willkommen. Entwicklungsumgebung, die Prüfungen, die eine Änderung
freigeben, und die Konventionen, die die Testsuite durchsetzt, stehen in
[CONTRIBUTING.md](../../CONTRIBUTING.md).

## Sicherheit

Melde Sicherheitslücken in Anti-REA selbst über [SECURITY.md](../../SECURITY.md), nicht in
öffentlichen Issues. Unter Bekannte Grenzen dokumentierte Design-Grenzen sind keine
Sicherheitslücken.

## Dokumentation

- [Chinesisch (vereinfacht)](README_zh.md) und [neun weitere Übersetzungen](.)
- [CONTRIBUTING.md](../../CONTRIBUTING.md): Entwicklungsumgebung und Freigabekriterien für Änderungen
- [SECURITY.md](../../SECURITY.md): Meldewege für Sicherheitslücken
- [LICENSE](../../LICENSE): MIT

## Lizenz

[MIT](../../LICENSE). Anti-REA dient dem Schutz von Software, die dir gehört oder zu deren Schutz du
autorisiert bist. Formate Dritter behalten ihre eigenen Spezifikationen.
