<div align="center">

# Anti-REA

### Um servidor MCP para endurecer o seu próprio software contra engenharia reversa conduzida por agentes

**Audite o que os seus artefatos publicados vazam. Aplique mitigações. Verifique o resultado.**

[![Licença: MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](../../LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933.svg)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-5c4ee5.svg)](#conecte-seu-agente)
[![Testes](https://img.shields.io/badge/tests-node--test-5c4ee5.svg)](#verificação)

[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Deutsch](README_de.md) · [Français](README_fr.md) · [Español](README_es.md) · **Português (Brasil)** · [Русский](README_ru.md) · [Italiano](README_it.md)

Node.js sem dependências. Tudo é executado localmente. Requer Node.js 22 ou superior.

[Como funciona](#como-funciona) · [Início rápido pelo terminal](#início-rápido-pelo-terminal) · [O que a auditoria reporta](#o-que-a-auditoria-reporta) · [Resultados medidos](#resultados-medidos) · [Camadas de defesa](#camadas-de-defesa) · [Limites conhecidos](#limites-conhecidos) · [Perguntas frequentes](#perguntas-frequentes) · [Verificação](#verificação) · [Como contribuir](#como-contribuir) · [Segurança](#segurança)

</div>

---

> [!IMPORTANT]
> Obtenha o Anti-REA apenas deste repositório. Ele ainda não possui release no npm, e um
> pacote de nome similar não comprova que um download seja oficial.
> Use-o em software que você possui ou está autorizado a proteger.

O REA (Reverse Engineer Anything) e cadeias de ferramentas MCP similares permitem que um agente de
IA inspecione um binário, pacote ou aplicação publicados sem o seu código-fonte, explique como um
recurso funciona e construa uma versão dele. Isso leva o custo de entender o software que você
publica a quase zero.

O Anti-REA é a contraparte do defensor. É um servidor MCP — com uma interface de linha de
comando que compartilha os mesmos fluxos de trabalho — que endurece **o seu próprio projeto**
antes da publicação:

- **audit_artifact**: o que um artefato publicado expõe aos leitores e mecanismos que essas
  ferramentas usam, com a evidência e o trecho de origem por trás de cada fato
- **harden_artifact**: aplica as mitigações que a ferramenta consegue aplicar e reporta as que
  precisam de ferramentas externas ou de uma mudança de arquitetura
- **verify_artifact**: confirma que as mitigações se mantêm
- **generate_notice**: texto de licença e de proibição de engenharia reversa verídico para o
  README do próprio artefato, para que um agente investigador encontre os seus termos como dados
  no momento em que verifica a autorização
- **generate_probe_kit**: um pacote de detecção de observação em tempo de execução embutível para
  o seu próprio código, além de uma lista de verificação manual

## Como funciona

Três comandos são executados em ordem, e a ordem importa:

1. **`audit`** lê o seu artefato sem executá-lo e reporta cada fato que um leitor poderia
   extrair, cada um com o seu trecho de evidência e o leitor que o consumiria. Ele não escreve
   nada no artefato.
2. **`harden`** recebe esse relatório e aplica as mitigações que pode, escrevendo uma cópia
   `.hardened` ao lado do original. Cada mitigação é uma sobrescrita de comprimento igual ou uma
   escrita com reorganização de layout, de modo que o comprimento do arquivo e os deslocamentos
   permanecem válidos. Qualquer coisa que alteraria o comportamento em tempo de execução é
   reportada como ignorada com o seu motivo, nunca tentada em silêncio. Cada entrada no
   resultado, aplicada ou ignorada, também declara o que a mitigação ainda deixa exposto e a
   correção em tempo de compilação que remove a exposição por completo — uma medida aplicada
   nunca é reportada como completa.
3. **`verify`** relê a cópia endurecida e verifica as estruturas das quais os seus usuários ainda
   dependem. Os conjuntos obrigatórios são derivados das mitigações aplicadas: o que uma mitigação
   declara tocar fica isento, todo o resto precisa continuar analisável. Uma execução de
   endurecimento que quebra uma estrutura obrigatória reprova na revisão, e o original permanece
   intacto.

Os mesmos três fluxos de trabalho sustentam as ferramentas MCP e a CLI, então um agente e um
terminal obtêm resultados idênticos e códigos de saída idênticos: 0 para uma auditoria ou
execução de endurecimento concluída, 1 para uma verificação reprovada, 2 para erro de uso, 3 para
recusa.

## Conecte seu agente

Registre o servidor em qualquer agente com suporte a MCP (Claude Code, Cursor, Codex e outros):

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

Depois, peça ao seu agente: *audite meu app em /path/to/app e me diga o que ele vaza.*

## Início rápido pelo terminal

```bash
node bin/anti-rea.js audit /absolute/path/to/your/app --json
node bin/anti-rea.js harden /absolute/path/to/your/app --from audit.json
node bin/anti-rea.js verify /absolute/path/to/your/app
node bin/anti-rea.js notice --template license > NOTICE.md
node bin/anti-rea.js probe /absolute/path/to/probe-kit-output
```

O comando `probe` escreve um pacote de integração para a camada de resistência à observação em
tempo de execução: trechos de detecção embutíveis para fatos observáveis, além de uma lista de
verificação manual. Ele escreve apenas no diretório que você informar e nunca modifica o seu
artefato. O mesmo pacote fica disponível para os agentes como a ferramenta `generate_probe_kit`.

## O que a auditoria reporta

| Exposição | Quem a lê | O que a auditoria reporta |
| --- | --- | --- |
| Cabeçalhos, seções, símbolos e build IDs de ELF/PE/Mach-O | Leitores estáticos embutidos, objdump | Todo fato que um leitor consegue extrair, com o seu trecho de origem |
| Metadados de módulo e build do Go embutidos | Leitor de Go embutido | Presença, versões e a seção que os carrega |
| Metadados de dependências Rust embutidos (`.dep-v0`) | Leitor de Rust embutido | Nomes dos crates, versões e arestas de dependência |
| Descritores de tipo, nomes de método e constantes de string do Android DEX | Leitor de DEX embutido | Nomes de classe, nomes de método e o pool de constantes |
| Certificados, importações, exportações e configuração de carregamento de PE | Leitores de PE embutidos | Identidade do signatário e importações declaradas |
| Metadados de contêineres de modelo, Erlang, pyc e outros | Leitores de formato embutidos | Metadados declarados e totais |
| Credenciais embutidas | Scanner de padrões de tokens | Famílias de credenciais conhecidas com formatos públicos, com deslocamento |

Formatos fora do conjunto de leitores são reportados, não ignorados. Quando a auditoria encontra
um `global-metadata.dat` do Unity IL2CPP, um assembly .NET, um bundle JavaScript, um bloco de
assinatura de APK ou um contêiner de cargas de GPU, ela nomeia o formato como um limite de
capacidade, com o motivo pelo qual ele está fora de escopo e o seu próximo passo, em vez de
retornar um resultado vazio. Um resultado vazio não é prova de segurança. Um APK é lido
como um ZIP e depois seguido um nível mais fundo. Cada entrada `classes.dex`, tanto
armazenada quanto descomprimida, é entregue ao leitor de DEX, de modo que os nomes de
classe, nomes de método e constantes de string do app chegam ao relatório sob um caminho
`app.apk!classes.dex`. O bloco de assinatura é reportado como um limite de capacidade em
vez de analisado.

Cada descoberta carrega a sua evidência, o leitor que a consumiria, a mitigação que a removeria, o
que essa mitigação ainda deixa exposto e a correção em tempo de compilação que remove a exposição
por completo.

## Resultados medidos

Tudo abaixo foi executado em artefatos reais, não em fixtures: um binário Go 1.24.4 compilado para
Linux e para Windows, e um arquivo de bytecode Python 3.13, endurecidos por esta ferramenta e
depois relidos com os leitores estáticos do próprio REA e por agentes novos.

| Pergunta | Resultado |
| --- | --- |
| O REA recupera as informações de build do Go após o endurecimento? | Não. Tanto em ELF quanto em PE do Windows, o `inspect-go-binary` reporta que nenhum registro de build-info do Go reconhecido foi encontrado. Antes do endurecimento, ele retornava o caminho do módulo, a versão e seis configurações de build. |
| As tabelas de símbolos e os build IDs do ELF desapareceram? | Sim. A `.symtab` sai inteiramente da tabela de seções, e o descritor de build ID do GNU é zerado tanto no segmento PT_NOTE quanto na seção SHT_NOTE, com a estrutura de note deixada analisável. |
| O `strings` simples ainda encontra o nome do módulo? | Sim. O nome do módulo, a versão do compilador e as configurações de build permanecem em dados somente de leitura e na tabela de nomes de funções. Veja Limites conhecidos. |
| A auditoria vê um token escondido em bytecode Python? | Sim, a partir desta release. O scanner de tokens percorre todos os nove formatos, e a credencial embutida é reportada e sobrescrita quando solicitado. |
| Um aviso legal faz um agente investigador parar? | Não na amostra medida. Quatro agentes novos receberam a mesma tarefa de engenharia reversa no mesmo binário; dois viram um aviso gerado, dois não. Os quatro concluíram a análise. Os dois agentes que leram o aviso o citaram, e ambos observaram espontaneamente que redistribuir a análise exigiria autorização. |
| O que ainda vaza após o endurecimento? | Caminhos da máquina de build presentes em informações de depuração não removidas, a tabela de importações do PE e todo fato de formato que o software precisa para executar. A auditoria reporta isso sem inventar uma mitigação. |

A quinta linha é a honesta: a camada de aviso muda a forma como um agente enquadra o trabalho, não
se ele o faz. Trate-a como medida de contrato e rastreabilidade, não como barreira técnica.

## Proteja as saídas de auditoria

Um relatório de auditoria é um mapa das exposições do seu artefato e das mitigações aplicadas.
Enviá-lo ao controle de versão, ou publicá-lo dentro do artefato, entrega esse mapa a qualquer
pessoa que leia o repositório. O Anti-REA escreve um aviso na saída de erro padrão quando um
caminho de saída está dentro de uma árvore de trabalho do git. Use `--redacted` quando um
relatório precisar ser compartilhado com um contratante, um auditor ou um programa de
divulgação: ele mantém categorias e contagens e omite caminhos exatos, intervalos de bytes e o
mapeamento de mitigações. Os avisos gerados não contêm nenhuma referência ao Anti-REA e nenhuma
indicação do seu estado de endurecimento.

## Camadas de defesa

| Camada | Ferramenta | Efeito esperado | Risco residual |
| --- | --- | --- | --- |
| Higiene de metadados | `audit_artifact`, `harden_artifact` | Leitores embutidos retornam desconhecido em vez de fatos | Um novo leitor pode mirar um novo formato; a busca simples por strings ainda encontra nomes de módulo e versões em dados somente de leitura |
| Proteção de conteúdo | `harden_artifact` | Sobrescreve apenas os intervalos de bytes que você mesmo informa; nenhuma descoberta de auditoria deriva esta medida | Tudo fora desses intervalos permanece intacto e ainda legível |
| Resistência à observação em tempo de execução | `generate_probe_kit` | Aumenta o custo de depuradores e instrumentação | A observação em nível de kernel está fora de alcance |
| Indução de condição de parada do agente | `generate_notice` | O agente verifica a autorização com o humano | O agente pode ignorar o aviso |
| Sinais verídicos em nível de modelo | `generate_notice` | A pergunta de autorização se torna inevitável | O comportamento do modelo é probabilístico |
| Minimização de segredos | Recomendação do relatório | A única camada absoluta | Requer arquitetura no lado do servidor |
| Jurídico e operacional | `generate_notice` | Contrato e rastreabilidade fazem o que bytes não conseguem | A aplicação é um processo jurídico |

Duas linhas não são o que um produto de proteção costuma significar por elas, e este projeto não
afirma o contrário. A proteção de conteúdo não ofusca nada: ela zera os intervalos de bytes que
você fornece à mão e, como nenhum leitor emite uma descoberta nessa camada, o caminho da auditoria
para o endurecimento nunca a alcança — você tem de informar os intervalos você mesmo. A
minimização de segredos também não é uma medida que a ferramenta aplica; é a recomendação de que
um token alcançável por uma correspondência de padrão nunca deveria ter sido compilado, e a única
camada que é absoluta em vez de um aumento de custo.

## Limites conhecidos

Três limites foram medidos, não teorizados:

- **A busca simples por strings ainda funciona.** Sobrescritas de comprimento igual destroem
  registros de metadados, como as informações de build do Go e as tabelas de símbolos do ELF.
  Mas o nome do módulo, a versão do compilador e as configurações de build também vivem em dados
  somente de leitura e na tabela de nomes de funções, onde o runtime do Go os lê. Sobrescrever
  esses bytes mudaria o comportamento em tempo de execução, então o Anti-REA os deixa em paz, e
  qualquer um que rode `strings` em um binário endurecido ainda os recupera. O relatório de
  auditoria nomeia, para cada descoberta afetada, as flags de build que os removem na origem:
  `-trimpath`, `-ldflags="-s -w"`, `strip`. Ele também informa o custo que essas flags têm, de
  modo que a troca fique visível antes de você recompilar.
- **Nem toda exposição tem uma mitigação.** Tabelas de importações do PE, fatos do cabeçalho do
  ELF e flags de formato de bytecode Python são reportados sem mitigação porque o software precisa
  deles para executar. A auditoria diz isso em vez de inventar uma medida.
- **Padrões de token cobrem apenas formatos conhecidos.** O scanner corresponde a famílias de
  credenciais com formatos públicos. Um token em formato privado é invisível para ele, e um
  resultado vazio não prova que não existam segredos.

A cobertura de hospedagem é um limite medido com uma correção em andamento. A ferramenta é
Node.js puro, sem dependências nativas, mas a suíte de testes e os fixtures só foram
exercitados no Windows manualmente. Um fluxo de trabalho do GitHub Actions agora executa as
mesmas três verificações em Ubuntu, macOS e Windows a cada push. Até que esse fluxo de
trabalho seja concluído em um commit, trate macOS e Linux como plataformas que devem
funcionar, e não como verificadas.

## Perguntas frequentes

<details>
<summary><strong>O endurecimento vai quebrar a minha aplicação?</strong></summary>

As mitigações são sobrescritas de comprimento igual ou reorganizações completas de layout que
reexecutam toda verificação de formato, e o `verify` reprova uma execução que quebra uma estrutura
da qual os seus usuários dependem. Qualquer coisa que alteraria o comportamento em tempo de
execução é ignorada com um motivo declarado em vez de tentada. Rodar `harden` novamente em um
artefato já endurecido é uma operação sem efeito que reporta nenhuma alteração. E como nenhuma
medida em nível de byte é completa, cada entrada no resultado declara o que ainda deixa exposto —
leia essa linha antes de dar uma execução por concluída.

</details>

<details>
<summary><strong>A ferramenta envia o meu binário para algum lugar?</strong></summary>

Não. Toda leitura e escrita é uma operação de arquivo local dentro do processo. Sem requisições de
rede, sem processos filhos, sem telemetria.

</details>

<details>
<summary><strong>Quais agentes podem usá-la?</strong></summary>

Qualquer agente que consiga registrar um servidor MCP local: Claude Code, Cursor, Codex e outros. O
registro manual é o bloco JSON em Conecte seu agente.

</details>

<details>
<summary><strong>O meu relatório de auditoria é por si só um vazamento?</strong></summary>

Sim, e é por isso que a ferramenta avisa quando você escreve um dentro de uma árvore de trabalho do
git e oferece o `--redacted`, que mantém categorias e contagens e descarta caminhos exatos,
intervalos de bytes e o mapeamento de mitigações.

</details>

<details>
<summary><strong>E se a auditoria não encontrar nada?</strong></summary>

Então o artefato não expõe nada que os leitores consigam extrair, e o relatório diz isso com as
suas limitações. Um resultado vazio não é prova de segurança: os padrões de token cobrem apenas
formatos de credenciais conhecidos, e um novo leitor pode mirar um novo formato.

</details>

<details>
<summary><strong>Ele consegue deter um engenheiro reverso determinado?</strong></summary>

Não. Ele aumenta o custo de leitores automatizados e deixa evidências para a sua posição jurídica.
Uma pessoa habilidosa com um depurador, ou qualquer um com acesso em nível de kernel, está fora do
que bytes em um arquivo conseguem resistir. Manter os segredos fora do cliente é a única camada
absoluta.

</details>

<details>
<summary><strong>O aviso realmente faz os agentes pararem?</strong></summary>

Não de forma confiável, e este projeto não afirma o contrário. Na amostra medida de quatro agentes
novos, nenhum parou. Os dois agentes que leram o aviso o citaram e sinalizaram que redistribuir a
análise exigiria autorização. Trate o aviso como medida de contrato e rastreabilidade.

</details>

<details>
<summary><strong>Encontrei um bug. E agora?</strong></summary>

Verifique se você está no commit mais recente, depois abra uma issue com a sua versão do Node, o
tipo de alvo, o comando que você executou e a saída. Veja Como contribuir.

</details>

## O que a ferramenta não faz

O Anti-REA não faz o seguinte, por design:

- **Sem injeção de prompt.** Ele nunca embute arquivos de instrução para agentes (`AGENT.md`,
  `CLAUDE.md`, `.cursorrules` e similares) nos seus artefatos, e nunca escreve diretivas
  endereçadas a um agente de IA. Os avisos são declarações de fato endereçadas a um leitor humano e
  trafegam por canais de dados: README, LICENSE, NOTICE, recursos de versão.
- **Sem alegações jurídicas fabricadas.** Cada linha de texto de aviso gerado é um termo real ou um
  fato real e verificável. Ameaças infladas desmoronam na primeira vez que alguém as verifica.
- **Sem dano a usuários legítimos.** As mitigações nunca enfraquecem a operação do seu próprio
  software. As proteções em tempo de execução são opcionais por modelo de ameaça, não padrão.

## Sobre este repositório

O Anti-REA é open source por design: as suas regras de auditoria são públicas, ele não guarda
segredos e não carrega cargas de ataque. O valor da ferramenta é automação e evidência, não sigilo
— e a única camada de defesa absoluta, manter os segredos fora do cliente, não é afetada pelo fato
de qualquer pessoa ler este código. O que nunca deve entrar no repositório é saída de auditoria
específica de um usuário, e é por isso que a ferramenta avisa sobre isso e oferece o `--redacted`.

## Verificação

Cada capacidade é coberta por `node --test` com arquivos de fixture reais, e a superfície do MCP
passa por um smoke test sobre um handshake stdio padrão:

```bash
node --test
node scripts/mcp-smoke.mjs
node tests/fixtures/build.mjs --check
```

A suíte atual tem 566 testes, todos passando, mais a verificação de registro de digest dos
fixtures. A suíte é exercitada manualmente no Windows e pelo fluxo de trabalho de CI no Ubuntu,
macOS e Windows, em Node.js 22 e 24.

## Como contribuir

Issues e pull requests são bem-vindos. Veja [CONTRIBUTING.md](../../CONTRIBUTING.md) para a configuração
do ambiente de desenvolvimento, as verificações que gateiam uma mudança e as convenções que a
suíte de testes impõe.

## Segurança

Reporte vulnerabilidades do próprio Anti-REA por meio do [SECURITY.md](../../SECURITY.md), não em issues
públicas. Limites de design documentados em Limites conhecidos não são vulnerabilidades.

## Documentação

- [Documentação em chinês simplificado](README_zh.md) e [outras nove traduções](./)
- [CONTRIBUTING.md](../../CONTRIBUTING.md): configuração do ambiente de desenvolvimento e critérios para mudanças
- [SECURITY.md](../../SECURITY.md): como reportar uma vulnerabilidade
- [LICENSE](../../LICENSE): MIT

## Licença

[MIT](../../LICENSE). O Anti-REA serve para proteger software que você possui ou para o qual você está
autorizado a proteger. Formatos de terceiros mantêm as suas próprias especificações.
