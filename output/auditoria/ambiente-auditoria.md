# Ambiente onde a auditoria foi executada

Registro do ambiente, para que os resultados possam ser reproduzidos e para que
se saiba exatamente o que foi (e o que não foi) verificado na prática.

**Data:** 27 de julho de 2026

---

## Sistema

| Item | Valor |
|---|---|
| Sistema operacional | macOS (Darwin 25.5.0) |
| Arquitetura | Apple Silicon (`/opt/homebrew`) |
| Python | 3.14.6 |
| OpenSSL | 3.6.3 (9 de junho de 2026) |
| Validação de certificado HTTPS | `CERT_REQUIRED` (ativada por padrão) — verificado |

---

## Dependências de sistema presentes

| Programa | Caminho | Versão |
|---|---|---|
| `rsync` | `/usr/bin/rsync` | openrsync (reporta "2.6.9 compatible" — ver nota) |
| `wimlib-imagex` | `/opt/homebrew/bin/wimlib-imagex` | 1.14.5 |
| `sudo` | `/usr/bin/sudo` | 1.9.17p2 |
| `diskutil` | `/usr/sbin/diskutil` | (Apple) |
| `hdiutil` | `/usr/bin/hdiutil` | (Apple) |
| `brew` | `/opt/homebrew/bin/brew` | presente |

**Ausentes (normal no macOS):** `parted`, `mkfs.vfat`, `wipefs`, `partprobe`,
`pkexec` — são utilitários exclusivos do Linux.

### Nota sobre o `rsync`

O comando `rsync --version` responde:

```
openrsync: protocol version 29
rsync version 2.6.9 compatible
```

A Apple substituiu o `rsync` original pelo **openrsync**, que apenas *finge* ser a
versão 2.6.9 para compatibilidade. Uma ferramenta automática de segurança leria
"2.6.9" (versão de 2006) e geraria um alarme falso grave. **Não é vulnerabilidade.**

---

## Ferramentas de análise automática

Nenhum scanner estava instalado neste ambiente:

| Ferramenta | Situação |
|---|---|
| `pip-audit` | não instalado |
| `bandit` | não instalado |
| `semgrep` | não instalado |
| `safety` | não instalado |
| `osv-scanner` | não instalado |
| `grype` | não instalado |
| `trivy` | não instalado |

**Isso não afetou o resultado do SCA:** o projeto não tem nenhuma dependência
Python de terceiros, então não há manifesto para escanear. A análise foi feita
por inspeção direta dos `import` do código.

**A análise SAST foi feita por leitura manual do código**, linha a linha, apoiada
por buscas direcionadas (`grep`) para injeção de comandos, segredos embutidos,
tratamento de erros e chamadas ao sistema.

---

## Limites do que foi verificado na prática

Registro honesto do que **não** foi executado:

| Não executado | Motivo |
|---|---|
| Fluxo real de apagar e gravar um pendrive | Destruiria os dados de um dispositivo físico. Verificado apenas por leitura de código. |
| Caminho de código específico do Linux | A auditoria rodou em macOS. A lógica do Linux (`parted`, `wipefs`, `mount`) foi analisada linha a linha, mas não executada. |
| Download real de uma ISO de ~5 GB | Não executado. A lógica foi validada por testes de unidade. |
| Comandos com `sudo` real | Deliberadamente evitado durante a auditoria. |
| DAST (teste com aplicação rodando na rede) | A aplicação não expõe serviço de rede. Ver `../relatorio-dast.md`. |

**Recomendação decorrente:** teste o fluxo completo com um pendrive descartável,
no macOS e se possível numa máquina Linux, antes de distribuir a versão corrigida.

---

## O que foi executado de verdade

| Verificação | Resultado |
|---|---|
| 36 testes automatizados de validação | Todos aprovados |
| Prova da injeção de comando (antes) | Comando injetado executou — falha confirmada |
| Prova da correção (depois) | Tratado como texto — correção confirmada |
| Construção da interface gráfica | Janela criada, todos os elementos presentes, sem erros |
| Permissões do log de auditoria | `-rw-------` (`0600`) — correto |
| Conteúdo do log de auditoria | Eventos registrados, nenhuma senha presente |
| Validação de sintaxe do Python | Sem erros |
