# Esteira automática (CI/CD) — guia em linguagem simples

Este documento explica o que foi montado, o que cada peça faz e **o que você
precisa fazer no site do GitHub** para tudo funcionar.

---

## Primeiro: o que é "CI/CD"?

São duas siglas em inglês que assustam mais do que deveriam.

**CI — Integração Contínua.** Toda vez que o código muda, um computador do
GitHub baixa o projeto numa máquina limpa e roda uma lista de conferências
sozinho. Se algo estiver errado, aparece um ✗ vermelho.

> É como ter um revisor que nunca dorme, nunca esquece de conferir nada e nunca
> diz "ah, esse detalhe deve estar ok".

**CD — Entrega Contínua.** A publicação automática de uma versão nova.

**Pipeline (esteira).** A sequência de conferências. Cada uma é uma "estação"
na linha de montagem; se o produto reprova numa estação, ele não segue adiante.

---

## O que foi montado

Quatro arquivos, cada um com um papel:

| Arquivo | Quando roda | Para que serve |
|---|---|---|
| `workflows/ci.yml` | A cada alteração | Confere que o programa funciona (estilo, erros, testes, em 6 combinações de sistema e versão do Python) |
| `workflows/security.yml` | A cada alteração **e toda segunda-feira** | Confere que as correções de segurança continuam no lugar |
| `workflows/release.yml` | Quando você publica uma versão | Publica com impressão digital e comprovante de origem |
| `dependabot.yml` | Semanalmente | Avisa quando as ferramentas da própria esteira têm atualização |

---

## A pipeline de segurança em detalhe

Ela foi montada em **duas camadas**, e essa divisão é a decisão mais importante
do desenho.

### Camada 1 — O guarda de regressão (Python puro, sempre bloqueia)

**O problema que ele resolve:** a auditoria corrigiu 17 falhas. Daqui a seis
meses, alguém mexe no código e desfaz uma delas sem perceber. Ninguém nota. A
falha volta.

**A solução:** um programa que confere, item por item, se cada correção continua
no lugar. Ele lê a *estrutura* do código (não faz busca de texto), então não se
engana com um comentário parecido.

São **24 proteções verificadas**. Alguns exemplos:

| Confere se... | Por quê |
|---|---|
| Nenhum valor variável é colado dentro de um comando de administrador | Era a falha mais grave da auditoria (injeção de comando) |
| A senha não vai na linha de comando | Outros usuários da máquina a veriam com `ps` |
| Só links `https://` são aceitos para download | Evita imagem do Windows adulterada no caminho |
| Discos com `/`, `/boot`, `/home` nunca aparecem na lista | Evita apagar o sistema de um Raspberry Pi |
| Nenhuma senha ou chave escrita no código | — |
| O SHA-256 continua sendo usado (nada de MD5) | MD5 é forjável |

**Por que ele é em Python puro, sem nenhuma ferramenta externa:** se o Semgrep
sair do ar, mudar de licença ou passar a exigir cadastro pago, a vigilância
essencial continua funcionando. Esta camada nunca depende de ninguém.

### "Quem vigia o vigia?"

Existe um problema clássico: **e se o próprio guarda estiver quebrado e
aprovando tudo?** Um verificador que sempre diz "está tudo bem" é *pior* que
verificador nenhum, porque dá falsa segurança.

Por isso existe o `teste_do_guarda.py`, que roda **antes** do guarda: ele pega o
código, desfaz de propósito cada correção (numa cópia temporária, nunca no
arquivo original) e confere que o guarda reclama de todas as 13.

> Isso não é teoria: quando montei esta esteira, esse autoteste **encontrou um
> defeito real no guarda**. A conferência do `set -eu` procurava esse texto em
> qualquer lugar do arquivo, então um comentário escrito `# sem set -eu` a
> enganava. Sem o autoteste, essa proteção estaria falsamente marcada como ativa.

### Camada 2 — Ferramentas externas (segunda opinião)

| Ferramenta | O que faz | Bloqueia? |
|---|---|---|
| **Bandit** | Analisador de segurança específico para Python | Só gravidade Alta |
| **Semgrep** | Busca padrões perigosos. Usa **9 regras escritas para este projeto** + catálogo público | Regras próprias sim; catálogo não |
| **CodeQL** | O analisador do próprio GitHub, muito profundo | Sim |
| **Gitleaks** | Procura senhas no **histórico** de commits | Não (avisa) |

**Por que a camada 2 bloqueia só nas falhas graves:** ferramentas automáticas
geram alarme falso. Uma esteira que trava o projeto por bobagem acaba sendo
desligada por todo mundo — e aí não protege nada. Melhor bloquear pouco e de
verdade do que bloquear tudo e ser ignorada.

Todas as exceções estão escritas com justificativa em `pyproject.toml`.
**Nenhuma regra de segurança foi desligada em bloco**: duas delas (S110 e S310)
são suprimidas linha a linha, com o motivo escrito ao lado no código — assim uma
ocorrência *nova* continua sendo barrada.

---

## Antes de enviar: rode a conferência na sua máquina

Você não precisa esperar o GitHub para saber se está tudo certo:

```bash
python3 verificar.py
```

Roda as mesmas conferências localmente, em segundos. **É seguro:** nada toca em
disco, nada formata, nada pede senha de administrador.

Resultado esperado:

```
  RESULTADO: tudo certo. O código está pronto para ser enviado.
```

---

## O QUE VOCÊ PRECISA FAZER NO GITHUB

A esteira só começa a funcionar depois destes passos. Nenhum deles é feito por
código — todos são cliques no site.

### Passo 1 — Fazer o primeiro commit ⚠️ obrigatório

**O repositório ainda não tem nenhum commit.** Até isso acontecer, nada roda.

```bash
git add .
git commit -m "Correções de segurança, auditoria e esteira de CI/CD"
git push -u origin main
```

Assim que você enviar, abra a aba **Actions** no GitHub e veja a esteira rodando
pela primeira vez.

### Passo 2 — Exigir que as conferências passem antes de aceitar alterações

Sem isto, a esteira **avisa** que há problema, mas não **impede** que o problema
entre. É a diferença entre um alarme e uma tranca.

No GitHub: **Settings → Branches → Add branch protection rule**

- Branch name pattern: `main`
- ✅ *Require status checks to pass before merging*
- Nos checks obrigatórios, escolha: **`CI aprovada`** e **`Segurança aprovada`**
- ✅ *Require a pull request before merging* (recomendado)

> Esses dois nomes existem justamente para isto: eles resumem todas as
> conferências, então você marca 2 caixas em vez de 11.

### Passo 3 — Ligar a varredura nativa de segredos (grátis)

**Settings → Code security and analysis**, e ative:

| Opção | Para que serve |
|---|---|
| **Secret scanning** | O GitHub avisa se uma senha ou chave for publicada |
| **Push protection** | O GitHub **impede** o envio antes de acontecer |
| **Dependabot alerts** | Avisos de vulnerabilidade em dependências |
| **Code scanning** | Recebe os resultados do CodeQL na aba Security |

### Passo 4 — Publicar a primeira versão (opcional)

```bash
git tag v1.0.0
git push origin v1.0.0
```

O resto é automático: a esteira roda todas as conferências e, se passarem,
publica uma Release com a impressão digital SHA-256 e um **comprovante de origem
criptográfico** emitido pelo GitHub.

Esse comprovante é a resposta possível ao risco residual **RR-02** ("o programa
não tem assinatura digital"). Quem baixar pode confirmar que o arquivo saiu
desta esteira, a partir deste código:

```bash
gh attestation verify win11_usb_creator.py --repo 1985epma/epma-windows-usb-creator
```

---

## Se uma conferência falhar, o que fazer?

Não entre em pânico — é para isso que ela existe. O que a mensagem significa:

| Falhou | O que aconteceu | O que fazer |
|---|---|---|
| **Guarda de segurança** | Uma correção da auditoria foi desfeita | Leia a mensagem: ela diz qual proteção caiu e por quê importa |
| **Autoteste do guarda** | O próprio guarda está quebrado | **Prioridade máxima:** a vigilância não está confiável |
| **Dependências de terceiros** | Alguém adicionou uma biblioteca externa | A mensagem lista os 4 passos a seguir |
| **Testes de validação** | Uma proteção parou de funcionar na prática | Veja qual dos 36 testes falhou |
| **Teste da interface** | A janela não abre ou falta um elemento | Foi exatamente esse tipo de defeito que apareceu durante a auditoria |
| **Ruff / Bandit / Semgrep** | Padrão perigoso ou erro de código | A mensagem aponta arquivo e linha |
| **CodeQL** | Falha encontrada pelo analisador do GitHub | Veja os detalhes na aba **Security** |

---

## Custo

**Zero.** Repositórios públicos no GitHub têm Actions, CodeQL, Dependabot e
varredura de segredos gratuitos e ilimitados.

Se o repositório for privado, há uma cota mensal gratuita de minutos; esta
esteira consome poucos minutos por execução.

---

## Uma limitação honesta

A esteira confere **muita coisa**, mas há um limite que nenhuma automação
resolve: ela **não testa o fluxo real de apagar e gravar um pendrive**. Isso
exigiria destruir os dados de um dispositivo físico dentro de um servidor do
GitHub — o que não é possível nem desejável.

Ou seja: a esteira garante que as *proteções* continuam no lugar, mas não
substitui um teste manual com um pendrive descartável antes de publicar uma
versão. Isso continua sendo responsabilidade humana.
