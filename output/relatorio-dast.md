# Relatório DAST — Teste com a Aplicação Rodando

> **Nota (v1.1.0):** este relatório registra a auditoria da **v1.0.0** e não foi reescrito. Controles
> que mudaram depois: a *confirmação em três etapas* (caixa + digitação + diálogo) foi substituída por
> *diálogo final sempre* + *digitação do identificador só para discos de alto risco* (grandes, com dados);
> o filtro de discos passou a ser **somente USB** (sem `mmc`/removível genérico); toda gravação é
> **verificada por releitura antes do eject**; a senha de administrador é conferida **antes** de mexer no
> pendrive e não fica retida na memória. Detalhes: `CHANGELOG.md` e `SECURITY.md`.

**Projeto:** EPMA Windows 11 Creator USB
**Data:** 27 de julho de 2026
**Status:** **NÃO REALIZADO**

---

## Resumo em linguagem simples

**O que é DAST:** é testar a aplicação **ligada e funcionando**, atacando-a de verdade pela rede, como faria um invasor — o oposto do SAST, que só lê o código parado.

**O DAST não foi realizado neste projeto, e o motivo não é uma falha de execução: é que não existe alvo para testar.**

Um teste DAST funciona assim: aponta-se uma ferramenta para um endereço na internet (por exemplo, `https://meusite.com.br`), e ela dispara milhares de requisições maliciosas contra aquele endereço para ver como o servidor reage.

**Seu projeto não tem endereço nenhum.** Ele é um programa que roda na máquina do usuário, como o Word ou a calculadora. Não existe servidor esperando conexões, não existe porta de rede aberta, não existe URL. Não há para onde apontar a ferramenta.

Você confirmou isso no início desta auditoria, quando perguntei sobre a URL de produção.

**Isso é uma ausência de risco, não um risco não avaliado.** Sistemas que não expõem serviço na rede simplesmente não podem ser atacados remotamente por essa via — a categoria inteira de ataque não existe para eles. É um resultado positivo do desenho do seu projeto, não uma lacuna na auditoria.

**Importante:** você me pediu explicitamente para nunca inventar ou simular resultados de DAST. Não inventei. Este relatório não contém nenhum resultado de teste, porque nenhum teste foi executado.

---

## Por que não foi possível executar

### Motivo real

O projeto é uma aplicação de **desktop** (interface gráfica Tkinter em Python), distribuída como um único arquivo `.py` executado localmente pelo usuário.

Evidências técnicas:

| Verificação | Resultado |
|---|---|
| Servidor web no código | Nenhum. Sem Flask, Django, FastAPI ou `http.server`. |
| Porta de rede em escuta | Nenhuma. Sem `socket.bind()`, sem `listen()`, sem servidor de qualquer tipo. |
| Endpoints / rotas HTTP | Nenhum. Não há API. |
| Sessões, cookies, tokens | Nenhum. Não há autenticação. |
| Comunicação de rede | Apenas **saída**: `urllib.request.urlopen()` para baixar a ISO. |
| Parâmetro `{URL_PRODUCAO}` | Não preenchido — não existe URL para este projeto. |

O único tráfego de rede é o programa **buscando** um arquivo na internet. Ele nunca **recebe** conexões. Um invasor externo não tem como alcançá-lo.

### Confirmação do responsável

No início da auditoria perguntei explicitamente se havia alguma URL onde a aplicação estivesse rodando. A resposta foi: **"Não existe URL — é só um programa local."**

---

## O que precisaria de você para um DAST ser possível

Registrando de forma objetiva, caso o projeto mude no futuro:

| Cenário | O que seria necessário | Aplicável hoje? |
|---|---|---|
| O projeto ganhar uma versão web | Uma URL acessível (produção ou homologação) e autorização por escrito para testá-la | Não |
| Existir uma API ou serviço de rede | Endereço, porta e credenciais de teste | Não |
| Existir um site institucional do projeto | A URL do site, e autorização do responsável | Não |

**Autorização é indispensável:** testes DAST disparam tráfego que provedores e sistemas de proteção interpretam como ataque real. Testar um endereço sem autorização documentada do dono é ilegal em vários países. Se um dia houver uma URL, será preciso confirmar por escrito que você é o responsável e autoriza os testes.

---

## O que foi feito no lugar

O DAST não pôde ser feito, mas **isso não deixou o comportamento em execução sem verificação alguma**. Registro com precisão o que foi e o que não foi testado, para não passar impressão errada.

### Testes dinâmicos que foram executados (localmente, sem rede)

| Teste | O que verificou | Resultado |
|---|---|---|
| **Injeção de comando — antes** | Executou o padrão antigo com um nome de arquivo malicioso | Comando injetado **executou** — falha confirmada |
| **Injeção de comando — depois** | Executou o padrão novo com o mesmo nome malicioso | Tratado como texto, **não executou** — correção confirmada |
| **Validação de endereço** | 7 casos (`http`, `ftp`, `file`, vazio, texto inválido, host oficial, host desconhecido) | Todos com o comportamento esperado |
| **Validação de identificador de disco** | 6 casos com `;`, aspas, `$(...)`, `../`, vazio, válido | Perigosos recusados, válido aceito |
| **Validação de arquivo ISO** | 5 casos (inexistente, vazio, pasta, pequeno demais, válido) | Todos corretos |
| **Permissões do log de auditoria** | Criou o arquivo e inspecionou as permissões reais | `-rw-------` (só o dono lê) — correto |
| **Segredos no log** | Verificou que a senha não chega a argumento de processo nem ao log | Confirmado |
| **Construção da interface** | Abriu a janela de fato e conferiu todos os elementos | Sem erros; todos presentes |

**Total: 36 verificações automatizadas, todas aprovadas.** O script está em `output/auditoria/testes_validacao.py` e pode ser reexecutado a qualquer momento com:

```bash
python3 output/auditoria/testes_validacao.py
```

Nenhum desses testes toca em disco, formata nada ou executa comandos como administrador.

### O que NÃO foi testado — e é bom você saber

Sendo rigoroso sobre os limites: os testes acima **não** substituem um DAST, e também não cobrem tudo. O que ficou sem verificação prática:

| Não testado | Por quê |
|---|---|
| **O fluxo real de apagar e gravar um pendrive** | Exigiria um pendrive físico e destruiria seus dados. Verificado apenas por leitura de código. |
| **O caminho específico do Linux** | Esta auditoria rodou em macOS. A lógica do Linux (`parted`, `wipefs`, `mount`) foi analisada linha a linha, mas não executada. |
| **O download real de uma ISO de 5 GB** | Não executado. A lógica de download, verificação SHA-256 e descarte foi validada por análise e testes de unidade. |
| **Comportamento com `sudo` real** | Não executado, para não rodar comandos privilegiados durante a auditoria. |

**Recomendação:** antes de distribuir a versão corrigida, teste o fluxo completo com um pendrive descartável — no macOS e, se possível, numa máquina Linux. As correções foram feitas com cuidado e cobertas por testes, mas nenhum teste substitui uma execução real do caminho principal.

---

## Conclusão

| Item | Situação |
|---|---|
| DAST realizado? | **Não** |
| Motivo | A aplicação não expõe nenhum serviço de rede. Não existe URL para testar. Confirmado pelo responsável. |
| É uma lacuna de segurança? | **Não.** É consequência do tipo de aplicação — e reduz a superfície de ataque. |
| Resultados inventados? | **Nenhum.** |
| Verificação alternativa | 36 testes dinâmicos locais, todos aprovados |
| Reavaliar quando? | Se o projeto passar a expor qualquer serviço de rede |

**Gravidade dos achados DAST: nenhuma, por ausência de testes — e não por ausência de falhas.** Esta distinção está registrada de propósito: um relatório DAST vazio nunca deve ser lido como "a aplicação passou nos testes".
