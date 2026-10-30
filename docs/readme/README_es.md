<div align="center">

# Anti-REA

### Un servidor MCP para reforzar tu propio software contra la ingeniería inversa impulsada por agentes

**Audita lo que filtran tus artefactos publicados. Aplica mitigaciones. Verifica el resultado.**

[![Licencia: MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](../../LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933.svg)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-5c4ee5.svg)](#conecta-tu-agente)
[![Pruebas](https://img.shields.io/badge/tests-node--test-5c4ee5.svg)](#verificación)

[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Deutsch](README_de.md) · [Français](README_fr.md) · **Español** · [Português (Brasil)](README_pt-BR.md) · [Русский](README_ru.md) · [Italiano](README_it.md)

Node.js sin dependencias. Todo se ejecuta en local. Requiere Node.js 22 o una versión posterior.

[Cómo funciona](#cómo-funciona) · [Inicio rápido](#inicio-rápido-desde-la-terminal) · [Qué informa la auditoría](#qué-informa-la-auditoría) · [Resultados medidos](#resultados-medidos) · [Capas de defensa](#capas-de-defensa) · [Límites conocidos](#límites-conocidos) · [Preguntas frecuentes](#preguntas-frecuentes) · [Verificación](#verificación) · [Contribuir](#contribuir) · [Seguridad](#seguridad)

</div>

---

> [!IMPORTANT]
> Obtén Anti-REA únicamente de este repositorio. Todavía no tiene publicación en npm, y un
> paquete de nombre similar no demuestra que una descarga sea oficial.
> Úsalo solo sobre software que poseas o para el que estés autorizado a proteger.

REA (Reverse Engineer Anything) y cadenas de herramientas similares basadas en MCP permiten que un
agente de inteligencia artificial inspeccione un binario, un paquete o una aplicación publicados
sin su código fuente, explique cómo funciona una funcionalidad y construya una versión de ella.
Eso lleva el costo de entender el software que publicas casi a cero.

Anti-REA es la contraparte del defensor. Es un servidor MCP —con una interfaz de línea de
comandos que comparte los mismos flujos de trabajo— que refuerza **tu propio proyecto** antes
de publicarlo:

- **audit_artifact**: lo que un artefacto publicado expone a los lectores y motores que usan
  esas herramientas, con la evidencia y el rango de origen detrás de cada hecho
- **harden_artifact**: aplica las mitigaciones que la herramienta puede aplicar e informa de
  las que requieren herramientas externas o un cambio de arquitectura
- **verify_artifact**: confirma que las mitigaciones se mantienen
- **generate_notice**: texto de licencia y de prohibición de ingeniería inversa veraz para el
  README propio de tu artefacto, de modo que un agente investigador se encuentre con tus
  términos como datos en el momento en que verifica la autorización
- **generate_probe_kit**: un paquete de detección de observación en tiempo de ejecución,
  integrable en tu propio código, más una lista de comprobación manual

## Cómo funciona

Tres comandos se ejecutan en orden, y el orden importa:

1. **`audit`** lee tu artefacto sin ejecutarlo e informa de cada hecho que un lector podría
   extraer, con su rango de evidencia y el lector que lo consumiría. No escribe nada en el
   artefacto.
2. **`harden`** toma ese informe y aplica las mitigaciones que puede, escribiendo una copia
   `.hardened` junto al original. Cada mitigación es una sobrescritura de igual longitud o una
   escritura de redisposición, de modo que la longitud del archivo y los desplazamientos siguen
   siendo válidos. Todo lo que cambiaría el comportamiento en tiempo de ejecución se informa
   como omitido con su motivo, nunca se intenta en silencio. Cada entrada del resultado,
   aplicada u omitida, indica también lo que la mitigación sigue dejando expuesto y la
   corrección en tiempo de compilación que elimina esa exposición por completo: una medida
   aplicada nunca se informa como completa.
3. **`verify`** vuelve a leer la copia reforzada y comprueba las estructuras de las que aún
   dependen tus usuarios. Los conjuntos requeridos se derivan de las mitigaciones aplicadas:
   lo que una mitigación declara que toca queda exento, todo lo demás debe seguir siendo
   analizable. Una ejecución de refuerzo que rompa una estructura requerida no pasa la
   revisión, y el original queda intacto.

Los mismos tres flujos de trabajo sostienen las herramientas MCP y la interfaz de línea de
comandos, de modo que un agente y una terminal llegan a las mismas conclusiones sobre el mismo artefacto. Los códigos de salida son el contrato de la terminal: 0 para una auditoría o una ejecución de refuerzo completadas, 1 para una verificación fallida, 2 para un error de uso, 3 para una negativa. MCP no tiene códigos de salida: 0 se asigna a `isError: false`, con el informe en el resultado, mientras que 1, 2 y 3 se asignan todos a `isError: true`: una negativa no es un éxito, y su informe sigue llevando `status: "refused"` y el campo `omitted_reason` que nombra cada campo ausente.

## Conecta tu agente

Registra el servidor con cualquier agente compatible con MCP (Claude Code, Cursor, Codex y
otros):

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

Después pide a tu agente: *audita mi aplicación en /path/to/app y dime qué expone.*

## Inicio rápido desde la terminal

```bash
node bin/anti-rea.js audit /absolute/path/to/your/app --json
node bin/anti-rea.js harden /absolute/path/to/your/app --from audit.json
node bin/anti-rea.js verify /absolute/path/to/your/app
node bin/anti-rea.js notice --template license > NOTICE.md
node bin/anti-rea.js probe /absolute/path/to/probe-kit-output
```

El comando `probe` escribe un paquete de integración para la capa de resistencia a la
observación en tiempo de ejecución: fragmentos de detección integrables para hechos
observables, más una lista de comprobación manual. Solo escribe en el directorio que indiques y
nunca modifica tu artefacto. El mismo paquete está disponible para los agentes mediante la
herramienta `generate_probe_kit`.

## Qué informa la auditoría

| Exposición | Quién lo lee | Qué informa la auditoría |
| --- | --- | --- |
| Cabeceras, secciones, símbolos e identificadores de compilación de ELF/PE/Mach-O | Lectores estáticos integrados, objdump | Todos los datos que un lector puede extraer, con su rango de origen |
| Metadatos de módulo y de compilación de Go incrustados | Lector de Go integrado | Presencia, versiones y la sección que los aloja |
| Metadatos de dependencias de Rust incrustados (`.dep-v0`) | Lector de Rust integrado | Nombres de crates, versiones y relaciones de dependencia |
| Descriptores de tipo, nombres de método y constantes de cadena de DEX de Android | Lector de DEX integrado | Nombres de clase, nombres de método y el grupo de constantes |
| Certificados, importaciones, exportaciones y configuración de carga de PE | Lectores de PE integrados | Identidad del firmante e importaciones declaradas |
| Metadatos de contenedores de modelos, Erlang, pyc y otros formatos | Lectores de formato integrados | Metadatos declarados y totales |
| Credenciales incrustadas | Escáner de patrones de tokens | Familias de credenciales conocidas con formatos públicos, con su desplazamiento |

Los formatos que quedan fuera del conjunto de lectores se informan, no se omiten. Cuando la
auditoría se encuentra con un `global-metadata.dat` de Unity IL2CPP, un ensamblado de .NET, un
paquete de JavaScript, un bloque de firmas de APK o un contenedor de cargas útiles de GPU,
nombra el formato como un límite de capacidad, con el motivo por el que queda fuera de alcance
y tu siguiente paso, en lugar de devolver un resultado vacío. Un resultado vacío no prueba la
seguridad. Un APK se lee como un ZIP y luego se sigue un nivel más profundo. Cada entrada
`classes.dex`, tanto almacenada como desinflada, se entrega al lector de DEX, de modo que
los nombres de clase, nombres de método y constantes de cadena de la aplicación llegan
al informe bajo una ruta `app.apk!classes.dex`. El bloque de firmas se informa como un
límite de capacidad en lugar de analizarse.

Cada hallazgo incluye su evidencia, el lector que lo consumiría, la mitigación que lo
eliminaría, lo que esa mitigación sigue dejando expuesto y la corrección en tiempo de
compilación que elimina la exposición por completo.

## Resultados medidos

Todo lo que sigue se ejecutó sobre artefactos reales, no sobre fixtures: un binario de Go
1.24.4 compilado para Linux y para Windows, y un archivo de código de bytes de Python 3.13,
reforzados por esta herramienta y luego vueltos a leer con los lectores estáticos del propio
REA y por agentes nuevos.

| Pregunta | Resultado |
| --- | --- |
| ¿REA recupera la información de compilación de Go tras el refuerzo? | No. Tanto en ELF como en PE de Windows, `inspect-go-binary` informa de que no se encontró ningún registro reconocido de información de compilación de Go. Antes del refuerzo devolvía la ruta del módulo, la versión y seis ajustes de compilación. |
| ¿Han desaparecido las tablas de símbolos de ELF y los identificadores de compilación? | Sí. `.symtab` abandona por completo la tabla de secciones, y el descriptor del identificador de compilación de GNU se pone a cero tanto en el segmento PT_NOTE como en la sección SHT_NOTE, dejando la estructura de nota analizable. |
| ¿`strings` sin más todavía encuentra el nombre del módulo? | Sí. El nombre del módulo, la versión del compilador y los ajustes de compilación permanecen en los datos de solo lectura y en la tabla de nombres de funciones. Consulta Límites conocidos. |
| ¿La auditoría detecta un token oculto en código de bytes de Python? | Sí, a partir de esta versión. El escáner de tokens se ejecuta sobre los nueve formatos, y la credencial incrustada se informa y se sobrescribe a petición. |
| ¿Un aviso legal hace que un agente investigador se detenga? | No en la muestra medida. Cuatro agentes nuevos recibieron la misma tarea de ingeniería inversa sobre el mismo binario; dos vieron un aviso generado y dos no. Los cuatro completaron el análisis. Los dos agentes que leyeron el aviso lo citaron, y ambos indicaron por iniciativa propia que redistribuir el análisis requeriría autorización. |
| ¿Qué sigue filtrándose tras el refuerzo? | Las rutas de la máquina de compilación procedentes de la información de depuración sin eliminar, la tabla de importaciones de PE y todos los datos de formato que el software necesita para ejecutarse. La auditoría los informa sin inventar una mitigación. |

La quinta fila es la honesta: la capa de avisos cambia cómo enfoca el agente el trabajo, no si
lo hace. Trátala como una medida de contrato y trazabilidad, no como una barrera técnica.

## Protege los resultados de tu auditoría

Un informe de auditoría es un mapa de las exposiciones de tu artefacto y de las mitigaciones
aplicadas. Confirmarlo en el control de versiones, o publicarlo dentro del artefacto, entrega
ese mapa a cualquiera que lea el repositorio. Anti-REA escribe una advertencia en la salida de
error estándar cuando una ruta de salida está dentro de un árbol de trabajo de git. Usa
`--redacted` cuando un informe deba compartirse con un contratista, un auditor o un programa
de divulgación: conserva categorías y recuentos y omite rutas exactas, rangos de bytes y la
correspondencia de mitigaciones. Los avisos generados no contienen ninguna referencia a
Anti-REA ni ninguna pista sobre tu estado de refuerzo.

## Capas de defensa

| Capa | Herramienta | Efecto esperado | Riesgo residual |
| --- | --- | --- | --- |
| Higiene de metadatos | `audit_artifact`, `harden_artifact` | Los lectores integrados devuelven desconocido en lugar de datos | Un lector nuevo puede apuntar a un formato nuevo; la búsqueda de cadenas sin más sigue encontrando nombres de módulo y versiones en los datos de solo lectura |
| Protección del contenido | `harden_artifact` | Sobrescribe solo los rangos de bytes que tú mismo indicas; ningún hallazgo de auditoría deriva esta medida | Todo lo que queda fuera de esos rangos permanece intacto y sigue siendo legible |
| Resistencia a la observación en tiempo de ejecución | `generate_probe_kit` | Eleva el costo de depuradores e instrumentación | La observación a nivel de núcleo queda fuera de alcance |
| Inducción de condiciones de parada en el agente | `generate_notice` | El agente verifica la autorización con el humano | El agente puede ignorar el aviso |
| Señales veraces a nivel de modelo | `generate_notice` | La pregunta por la autorización se vuelve ineludible | El comportamiento del modelo es probabilístico |
| Minimización de secretos | Recomendación del informe | La única capa absoluta | Requiere una arquitectura del lado del servidor |
| Aspectos legales y operativos | `generate_notice` | El contrato y la trazabilidad consiguen lo que los bytes no pueden | El cumplimiento es un proceso legal |

Dos filas no son lo que un producto de protección suele entender por ellas, y este proyecto no
afirma lo contrario. La protección del contenido no ofusca nada: pone a cero los rangos de bytes
que tú mismo indicas a mano y, como ningún lector emite un hallazgo en esa capa, la ruta de la
auditoría al refuerzo nunca llega a ella: tienes que indicar los rangos tú mismo. La
minimización de secretos tampoco es una medida que aplique la herramienta; es la recomendación
de que un token alcanzable por una coincidencia de patrón nunca debería haberse compilado, y la
única capa que es absoluta en lugar de un aumento de coste.

## Límites conocidos

Se midieron tres límites, no se teorizaron:

- **La búsqueda de cadenas sin más sigue funcionando.** Las sobrescrituras de igual longitud
  destruyen registros de metadatos como la información de compilación de Go y las tablas de
  símbolos de ELF. Pero el nombre del módulo, la versión del compilador y los ajustes de
  compilación también residen en los datos de solo lectura y en la tabla de nombres de
  funciones, donde los lee el tiempo de ejecución de Go. Sobrescribir esos bytes cambiaría el
  comportamiento en tiempo de ejecución, así que Anti-REA no los toca, y cualquiera que
  ejecute `strings` sobre un binario reforzado sigue recuperándolos. El informe de auditoría
  nombra, para cada hallazgo afectado, las opciones de compilación que los eliminan en el
  origen: `-trimpath`, `-ldflags="-s -w"`, `strip`. También indica el coste que tienen esas
  opciones, de modo que la contrapartida sea visible antes de volver a compilar.
- **No todas las exposiciones tienen mitigación.** Las tablas de importaciones de PE, los
  datos de la cabecera de ELF y los indicadores de formato del código de bytes de Python se
  informan sin mitigación porque el software los necesita para ejecutarse. La auditoría lo
  dice en lugar de inventar una medida.
- **Los patrones de tokens solo cubren formatos conocidos.** El escáner empareja familias de
  credenciales con formatos públicos. Un token en un formato privado le resulta invisible, y
  un resultado vacío no prueba que no existan secretos.

La cobertura de sistemas es un límite medido con una corrección en marcha. La herramienta
es puramente Node.js sin dependencias nativas, pero el conjunto de pruebas y los fixtures
solo se han ejecutado en Windows a mano. Un flujo de trabajo de GitHub Actions ejecuta
ahora las mismas tres comprobaciones en Ubuntu, macOS y Windows en cada push. Hasta que
ese flujo de trabajo se complete en un commit, trata macOS y Linux como sistemas de los
que se espera que funcionen, no como verificados.

## Preguntas frecuentes

<details>
<summary><strong>¿El refuerzo romperá mi aplicación?</strong></summary>

Las mitigaciones son sobrescrituras de igual longitud o redisposiciones completas que vuelven
a ejecutar todas las comprobaciones de formato, y `verify` hace fallar una ejecución que rompa
una estructura de la que dependen tus usuarios. Todo lo que cambiaría el comportamiento en
tiempo de ejecución se omite con un motivo declarado en lugar de intentarse. Volver a ejecutar
`harden` sobre un artefacto ya reforzado es una operación sin efecto que informa de que no hay
cambios. Y como ninguna medida a nivel de bytes es completa, cada entrada del resultado indica
lo que sigue dejando expuesto: lee esa línea antes de dar por terminada una ejecución.

</details>

<details>
<summary><strong>¿La herramienta sube mi binario a algún sitio?</strong></summary>

No. Todas las lecturas y escrituras son operaciones de archivo locales dentro del proceso. Sin
peticiones de red, sin procesos secundarios, sin telemetría.

</details>

<details>
<summary><strong>¿Qué agentes pueden usarla?</strong></summary>

Cualquier agente que pueda registrar un servidor MCP local: Claude Code, Cursor, Codex y
otros. El registro manual es el bloque JSON de la sección Conecta tu agente.

</details>

<details>
<summary><strong>¿Mi informe de auditoría es en sí una filtración?</strong></summary>

Sí, y por eso la herramienta avisa cuando escribes uno dentro de un árbol de trabajo de git y
ofrece `--redacted`, que conserva categorías y recuentos y elimina rutas exactas, rangos de
bytes y la correspondencia de mitigaciones.

</details>

<details>
<summary><strong>¿Y si la auditoría no encuentra nada?</strong></summary>

Entonces el artefacto no expone nada que los lectores puedan extraer, y el informe lo dice con
sus limitaciones. Un resultado vacío no prueba la seguridad: los patrones de tokens solo
cubren formatos de credenciales conocidos, y un lector nuevo puede apuntar a un formato nuevo.

</details>

<details>
<summary><strong>¿Puede detener a un ingeniero inverso decidido?</strong></summary>

No. Aumenta el costo de los lectores automatizados y deja evidencia para tu posición legal.
Una persona experta con un depurador, o cualquiera con acceso a nivel de núcleo, está fuera de
lo que los bytes de un archivo pueden resistir. Mantener los secretos fuera del cliente es la
única capa absoluta.

</details>

<details>
<summary><strong>¿El aviso realmente hace que los agentes se detengan?</strong></summary>

No de forma fiable, y este proyecto no afirma lo contrario. En la muestra medida de cuatro
agentes nuevos, ninguno se detuvo. Los dos agentes que leyeron el aviso lo citaron y señalaron
que redistribuir el análisis requeriría autorización. Trata el aviso como una medida de
contrato y trazabilidad.

</details>

<details>
<summary><strong>Encontré un error. ¿Y ahora?</strong></summary>

Comprueba que estás en el último commit, luego abre un issue con tu versión de Node, el tipo
de destino, el comando que ejecutaste y la salida. Consulta Contribuir.

</details>

## Fronteras

Anti-REA no hace lo siguiente, por diseño:

- **Sin inyección de prompts.** Nunca incluye archivos de instrucciones para agentes
  (`AGENT.md`, `CLAUDE.md`, `.cursorrules` y similares) dentro de tus artefactos, y nunca
  escribe directivas dirigidas a un agente de inteligencia artificial. Los avisos son
  declaraciones de hechos dirigidas a un lector humano y viajan por canales de datos: README,
  LICENSE, NOTICE, recursos de versión.
- **Sin afirmaciones legales falsas.** Cada línea del texto de aviso generado es un término
  real o un hecho real y verificable. Las amenazas infladas se derrumban la primera vez que
  alguien las verifica.
- **Sin daño a usuarios legítimos.** Las mitigaciones nunca debilitan el funcionamiento propio
  de tu software. Las protecciones en tiempo de ejecución son opcionales según el modelo de
  amenazas, no valores predeterminados.

## Acerca de este repositorio

Anti-REA es de código abierto por diseño: sus reglas de auditoría son públicas, no guarda
secretos y no contiene cargas útiles de ataque. El valor de la herramienta es la automatización
y la evidencia, no el secreto — y la única capa de defensa absoluta, mantener los secretos
fuera del cliente, no se ve afectada porque alguien lea este código. Lo que nunca debe entrar
en el repositorio es la salida de auditoría específica de un usuario, y por eso la herramienta
avisa sobre ello y ofrece `--redacted`.

## Verificación

Todas las capacidades están cubiertas por `node --test` con archivos de fixtures reales, y la
superficie MCP se somete a una prueba de humo mediante un saludo estándar por stdio:

```bash
node --test
node scripts/mcp-smoke.mjs
node tests/fixtures/build.mjs --check
```

El conjunto actual tiene 595 pruebas, todas pasan, más la comprobación de registro de resúmenes
de los fixtures. El conjunto se ejecuta a mano en Windows y mediante el flujo de trabajo de CI
en Ubuntu, macOS y Windows, con Node.js 22 y 24.

## Contribuir

Tanto los issues como las pull requests son bienvenidos. Consulta
[CONTRIBUTING.md](../../CONTRIBUTING.md) para la configuración del entorno de desarrollo, las
comprobaciones que condicionan un cambio y las convenciones que exige el conjunto de pruebas.

## Seguridad

Informa de las vulnerabilidades del propio Anti-REA mediante [SECURITY.md](../../SECURITY.md), no
en issues públicos. Los límites de diseño documentados en Límites conocidos no son
vulnerabilidades.

## Documentación

- [Instrucciones en chino simplificado](README_zh.md) y [otras nueve traducciones](./)
- [CONTRIBUTING.md](../../CONTRIBUTING.md): configuración del entorno de desarrollo y condiciones
  para aceptar un cambio
- [SECURITY.md](../../SECURITY.md): cómo informar de una vulnerabilidad
- [LICENSE](../../LICENSE): MIT

## Licencia

[MIT](../../LICENSE). Anti-REA sirve para proteger software que posees o para el que estés
autorizado a proteger. Los formatos de terceros conservan sus propias especificaciones.
