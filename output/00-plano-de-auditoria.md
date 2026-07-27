# Plano de Auditoria de Segurança — EPMA Windows 11 Creator USB

**Data:** 27 de julho de 2026
**Auditor:** Análise DevSecOps
**Projeto:** EPMA Windows 11 Creator USB (`win11_usb_creator.py`)
**Repositório:** https://github.com/1985epma/epma-windows-usb-creator

---

## Antes de tudo: que tipo de programa é este?

Isso muda **tudo** na auditoria, então vale explicar em linguagem simples.

Existem dois tipos muito diferentes de aplicação:

| Tipo | Exemplo | Onde roda | Quem pode atacar |
|---|---|---|---|
| **Aplicação web** (site/servidor) | Um internet banking | Num servidor na internet | Qualquer pessoa no mundo |
| **Aplicação de desktop** (programa local) | O Word, o WhatsApp do PC | No computador do próprio usuário | Quem já tem acesso àquele computador, ou quem consegue enganar o usuário |

**Este projeto é do segundo tipo.** É um programa que abre uma janela no computador da pessoa, com botões, para baixar o Windows 11 e gravar num pendrive. Não existe servidor, não existe site, não existe banco de dados, não existe login.

### O que isso significa na prática para esta auditoria

Três consequências importantes, e é melhor você saber delas agora do que se surpreender no fim:

1. **Não há URL para testar.** Você confirmou isso. Portanto o **DAST** (o teste com a aplicação rodando, simulando um invasor pela internet) **não será realizado** — não por falha minha, mas porque não existe alvo de rede para testar. Isso ficará registrado de forma honesta no relatório, sem nenhum resultado inventado.

2. **Não há senhas ou chaves escondidas no código para migrar.** Verifiquei: o programa não usa nenhuma senha, chave de API ou token próprio. Então a lista de "variáveis de ambiente para cadastrar" será curta e composta apenas por **ajustes opcionais de segurança** que eu vou criar — não por segredos vazados. Isso é uma boa notícia.

3. **Em compensação, este programa tem um risco que sites normais não têm: ele roda comandos como administrador da máquina e apaga discos inteiros.** É aqui que mora o perigo real deste projeto, e é onde vou concentrar a análise. Um erro aqui não vaza dados de clientes — apaga o HD da pessoa ou entrega o controle total do computador dela.

---

## Vocabulário: os 5 tipos de análise, em uma frase cada

| Sigla | Nome completo | O que é, em português claro |
|---|---|---|
| **SCA** | *Software Composition Analysis* | Conferir os "ingredientes de terceiros" — os pedaços de código feitos por outras pessoas que o seu programa usa — e ver se algum deles tem defeito de segurança conhecido. |
| **SAST** | *Static Application Security Testing* | Ler o código-fonte parado, linha por linha, procurando falhas — como um revisor lendo um contrato antes de assinar. |
| **STRIDE** | (sigla das 6 categorias) | Imaginar sistematicamente todas as formas de atacar cada peça do sistema, seguindo 6 tipos de ameaça, para não esquecer nenhuma. |
| **OWASP Top 10** | *Open Worldwide Application Security Project* | Conferir o projeto contra a lista das 10 falhas de segurança mais comuns do mundo, publicada por uma organização de referência. |
| **DAST** | *Dynamic Application Security Testing* | Testar a aplicação **ligada e funcionando**, atacando-a de verdade de fora, como faria um invasor. |

---

## Escala de gravidade (usada em TODOS os relatórios)

| Nível | O que significa na prática |
|---|---|
| **Crítica** | Permite estrago grave e é fácil de explorar. Corrigir imediatamente. |
| **Alta** | Permite estrago grave, mas exige alguma condição especial. Corrigir com urgência. |
| **Média** | Estrago limitado, ou exige bastante esforço do atacante. Corrigir no curto prazo. |
| **Baixa** | Estrago pequeno. Corrigir quando for conveniente. |
| **Info** | Não é falha, é uma observação ou boa prática recomendada. |

---

## As etapas que vou seguir

Vou executar **uma de cada vez**, na ordem, e te explicar o resultado de cada uma antes de passar para a próxima.

### Fase 1 — Auditoria (só olhar, não mexer)

- [ ] **Etapa 1 — SCA:** levantar todo código de terceiros usado (bibliotecas Python e também os programas do sistema que o projeto chama, como `parted` e `rsync`), e verificar vulnerabilidades conhecidas.
- [ ] **Etapa 2 — SAST:** ler as 800 linhas do código procurando falhas, com atenção especial a:
  - injeção de comandos (fazer o programa executar uma ordem que o atacante escreveu) — o equivalente do "SQL Injection" neste projeto, já que aqui não há banco de dados;
  - senhas, chaves e tokens escritos direto no código;
  - mensagens de erro que revelam informação demais;
  - falta de conferência dos dados que o usuário digita;
  - registros (logs) que gravem coisas sigilosas.
- [ ] **Etapa 3 — STRIDE:** modelar as ameaças componente por componente (a janela do programa, a parte que executa comandos como administrador, o armazenamento local e o pendrive, e as conexões externas com a Microsoft e com os instaladores de programas).
- [ ] **Etapa 4 — OWASP Top 10 2021:** classificar cada uma das 10 categorias como Mitigado / Parcial / Exposto, com evidência.
- [ ] **Etapa 5 — DAST:** **não realizável** neste projeto. Vou registrar o motivo real e explicar o que precisaria existir para ser possível.

### Fase 2 — Correções (mexer no código, sem mudar o que o programa faz)

Regra que vou seguir à risca: **nenhuma funcionalidade nova, nenhuma mudança no comportamento que você já conhece.** Só blindagem.

- [ ] **Etapa 6** — Eliminar a injeção de comandos na parte que roda como administrador.
- [ ] **Etapa 7** — Corrigir as verificações de segurança que "falham liberando" (quando o programa não consegue confirmar que um disco é externo, hoje ele assume que é — vou inverter para assumir que não é).
- [ ] **Etapa 8** — Validar o endereço de download e conferir a integridade do arquivo baixado.
- [ ] **Etapa 9** — Melhorar o tratamento de erros e os registros (logs), sem gravar nada sigiloso.
- [ ] **Etapa 10** — Melhorar o cuidado com a senha de administrador em memória.
- [ ] **Etapa 11** — Demais boas práticas (conferência de última hora antes de apagar o disco, permissões de arquivo, etc.).
- [ ] **Etapa 12** — Testar que o programa continua funcionando exatamente como antes.

### Fase 3 — Relatórios

- [ ] **Etapa 13** — Gerar os 5 relatórios individuais em `output/`.
- [ ] **Etapa 14** — Gerar o relatório consolidado final em `output/relatorio-consolidado-seguranca.md`.
- [ ] **Etapa 15** — Criar a pasta `output/auditoria/` e organizar os documentos.
- [ ] **Etapa 16** — Entregar o resumo geral, a lista de variáveis de ambiente e os riscos que sobraram.

---

## O que eu NÃO vou fazer

Para deixar claro e evitar mal-entendidos:

- **Não vou inventar resultado de DAST.** Se não posso testar, o relatório dirá "Não realizado" e explicará por quê.
- **Não vou inventar códigos de vulnerabilidade (CVE).** Só reporto vulnerabilidade que eu possa fundamentar de fato.
- **Não vou mudar o que o programa faz.** Ele vai continuar baixando a ISO e gravando o pendrive do mesmo jeito.
- **Não vou executar os comandos perigosos** (apagar disco, formatar) durante os testes. A verificação será por leitura de código e testes que não tocam em disco de verdade.
- **Não vou publicar nada em lugar nenhum.** Tudo fica nos arquivos locais do projeto.

---

## Formato de saída

Não consigo gerar PDF neste ambiente. **Todos os relatórios serão salvos em arquivos Markdown (`.md`) na pasta `output/`** — são arquivos de texto que abrem em qualquer editor e ficam bem formatados no GitHub. Se quiser PDF depois, dá para converter facilmente.
