# Pasta de auditoria — evidências e materiais de apoio

Esta pasta guarda o **material bruto** que sustenta os relatórios: os testes que
podem ser reexecutados e as provas técnicas dos achados.

Os relatórios em si estão um nível acima, em [`../`](../).

---

## Conteúdo

| Arquivo | O que é |
|---|---|
| `testes_validacao.py` | 44 testes automatizados que comprovam cada correção. Reexecutável. |
| `evidencia-injecao.md` | Prova técnica do achado mais grave (injeção de comando) — antes e depois. |
| `ambiente-auditoria.md` | Versões e ferramentas do ambiente onde a auditoria rodou. |

---

## Como reexecutar os testes

Na raiz do projeto:

```bash
python3 output/auditoria/testes_validacao.py
```

Resultado esperado:

```
RESULTADO: todas as 44 verificações passaram.
```

**Estes testes são seguros:** não tocam em nenhum disco, não formatam nada e não
executam comandos como administrador. Podem ser rodados a qualquer momento.

**Rode-os sempre depois de alterar o `win11_usb_creator.py`.** Se algum falhar,
é sinal de que uma proteção foi desfeita sem querer.

---

## Como conferir que você está com o código auditado

```bash
shasum -a 256 win11_usb_creator.py
```

Deve resultar em:

```
636fe796927e49842e08857efdc042bcbd0d7223cde0818a0f50b376cab771e2
```

Se o valor for diferente, o arquivo foi alterado depois da auditoria — o que é
normal se você mesmo mexeu nele, mas os relatórios passam a se referir a uma
versão anterior.
