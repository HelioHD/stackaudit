# stackaudit

> Read this in [English](./README.md).

Uma CLI *passiva por padrão* que audita apps pequenos em **Supabase + Vercel + Render**
em busca de misconfigurations e gera achados prontos pro relatório de pentest.

`npx stackaudit <url>` olha só o que um navegador já recebe — o bundle JS, os headers HTTP,
os source maps, `/.env`, `/.git/config` — detecta o stack de plataformas e reporta o que
está exposto. Um modo **ativo** opcional prova a exposição de tabelas do Supabase *sem
baixar uma única linha*.

Faz parte do ferramental **Delfino Security** e emite o
[`finding.schema.json`](./schema/finding.schema.json) compartilhado, então a saída alimenta
o gerador de relatório (e conversa com o `sealcheck`, a ferramenta irmã de JWT) sem cola
manual.

---

## Postura legal (leia primeiro)

Feita pra rodar contra sistemas que você tem autorização pra testar. Os padrões são
conservadores de propósito.

| Modo | Precisa | O que faz |
|---|---|---|
| **passivo** (padrão) | uma URL | Só o que um navegador já baixa: bundle, headers, source maps, `/.env`, `/.git/config`, `/.well-known`. Sem auth, sem chamadas de API. |
| **ativo** (`--authorized`) | URL **e** a flag explícita `--authorized` | Pode consultar o endpoint público (anon) do Supabase com **`HEAD` + `Prefer: count=exact`**, lendo o total de linhas do header `Content-Range`. |
| **config** (v2) | tokens do dono | Fora do escopo deste MVP. Stub; sai com um aviso. |

Garantias duras, impostas no código e cobertas por testes:

- **Contagem, nunca leitura.** O check ativo de tabela usa `HEAD` + `Prefer: count=exact`.
  O total vem do `Content-Range`; **nenhuma linha é baixada**. Um teste garante que toda
  requisição a `/rest/v1` é `HEAD`.
- **`200 []` não prova RLS desligado.** RLS ligado sem policy correspondente também devolve
  vazio. A saída diz isso e marca o caso pra revisão manual.
- **Permissividade de escrita não é testada.** INSERT/UPDATE nunca são tentados — testar
  isso é escrever no banco de outra pessoa.
- **Segredo achado é reportado, nunca usado.** Uma chave Stripe/AWS/Supabase encontrada é
  redigida e reportada. A ferramenta **nunca** a valida chamando a API do dono — isso já
  seria uso da credencial. Um teste garante que nenhum segredo achado é enviado a lugar nenhum.

---

## Começo rápido (2 minutos)

```bash
# scan passivo (padrão), saída legível
npx stackaudit https://seu-app.exemplo

# saída de máquina pra pipeline de relatório
npx stackaudit https://seu-app.exemplo --format json  -o findings.json
npx stackaudit https://seu-app.exemplo --format sarif -o results.sarif
npx stackaudit https://seu-app.exemplo --format html  -o report.html

# modo ativo — exige autorização explícita, só contagem no Supabase
npx stackaudit https://seu-app.exemplo --mode active --authorized
```

Do código-fonte:

```bash
npm install
npm run build
node dist/cli.js https://seu-app.exemplo
npm test
```

---

## Exemplo de saída (capturado em fixtures locais)

Os trechos abaixo saíram de rodar o stackaudit contra a fixture em
[`test/fixtures.ts`](./test/fixtures.ts) — um app falso com segredos plantados,
obviamente falsos. As capturas completas estão em [`examples/`](./examples).

```
../ stackaudit  https://demo-app.example
mode: active   platforms: vercel, supabase   requests: 14

CRITICAL 3  HIGH 5  MEDIUM 6  LOW 3  INFO 6

[CRITICAL] Supabase secret key (sb-secret, role=service_role) in client bundle
    ... This key bypasses RLS and grants full database access.

[HIGH] Sensitive table "users" exposes 1452 rows to the anon key
    HEAD + Prefer: count=exact on users returned Content-Range total 1452 using only the public key. No rows were downloaded. ...

[REVIEW] Review: Table "products" exposes 320 rows to the anon key
    ... um catálogo público pode ser intencional; classifique manualmente.
```

A palavra de severidade é sempre escrita (nunca só cor), as cores seguem a paleta CLI da
Delfino e `NO_COLOR` é respeitado. O HTML é uma página única com os tokens da Delfino UI
(Space Grotesk + IBM Plex Mono, acento `#0057FF`, cores de severidade, claro/escuro):
[`examples/report.html`](./examples/report.html).

---

## Checks (MVP)

**Supabase**
- Chave secreta no bundle — detecta **os dois formatos**: legado (JWT decodificado; a claim
  `role` é lida, não adivinhada por regex) e os novos prefixos `sb_secret_` / `sb_publishable_`.
- *(ativo)* Contagem de linhas via `HEAD` + count, com classificação de sensibilidade
  (nomes sugerindo email/cpf/telefone → **ALTA**, resto → **REVISAR**).
- *(ativo)* Bucket listável (o list é um `POST`; "só lê" inclui esse POST, e isso é declarado).
- *(ativo)* `GET /auth/v1/settings` — signup aberto / autoconfirm.
- *(ativo)* Presença do endpoint `pg_graphql` e RPCs referenciadas no cliente, pra revisar
  uso indevido de `SECURITY DEFINER`.

**Vercel / front**
- Segredos no bundle usando as **regras do gitleaks** (ver abaixo).
- Source maps públicos.
- Headers de segurança (CSP, HSTS, `frame-ancestors` / clickjacking, Referrer-Policy) —
  headers ficam **só aqui**.
- Bypass de origem via `*.vercel.app` acessível.

**Render / API**
- Exposição de `/.env`, `/.git/config`, `/.git/HEAD`.
- CORS refletido com credentials.
- Stack trace vazado em produção.
- Bypass de origem via `*.onrender.com` acessível.

Cada check é um plugin com metadados: `id`, `platform`, `modeRequired`, `defaultSeverity`,
`reference`, `remediation` (ver [`src/checks`](./src/checks)).

---

## Posicionamento honesto

O stackaudit **não** substitui estes — ele preenche a lacuna entre eles:

- **supasec** (`npx supasec scan`) e outros scanners auditam o Supabase isolado.
- O **Security Advisor do Supabase** roda lints do Postgres (o conjunto `splinter`, ex.:
  `0013_rls_disabled_in_public`) de *dentro* do projeto, com acesso de dono.

O que o stackaudit acrescenta: as **três plataformas juntas** (o stack real de app pequeno
brasileiro), **bypass de origem** e saída no **schema de relatório compartilhado**. Ele prova
exposição *de fora, sem tocar no dado*. O futuro modo **config** vai rodar o `splinter` em
vez de reimplementar os lints — reusar a fonte oficial é o certo.

> "Checks focados nas misconfigs de BaaS que scanners genéricos não modelam, provando
> exposição sem tocar no dado."

---

## Por que essa arquitetura

| Decisão | Escolha | Descartado | Motivo |
|---|---|---|---|
| Linguagem | **TypeScript / npx** | Go, Python | A comunidade dessas plataformas é JS/TS e `npx` é zero-install. O ambiente aqui é só Node (sem Python, sem Go). |
| Estrutura | **plugins com metadados** | scanner monolítico | As plataformas mudam rápido; cada check atualiza isolado e carrega severidade, modo e correção próprios. |
| Teste de RLS | **`HEAD` + count** | ler linhas e "não salvar" | Prova a exposição sem baixar dado pessoal de ninguém. |
| Modo padrão | **passivo** | ativo por padrão | Passivo só faz o que um navegador faria; tocar numa API exige `--authorized` explícito. |
| Modo config | **v2, reusando splinter** | reimplementar os lints | Três APIs que mudam sem aviso triplicam manutenção; o `splinter` já é a fonte oficial. |
| Saída | **`finding.schema.json` compartilhado** | formato próprio | Uma ferramenta alimenta a outra sem cola manual. |

### Por que cada dependência

- **TypeScript** — tipos pegam erro de plugin (severidade errada, campo faltando) em tempo
  de build, antes do Ajv rodar.
- **ajv** + **ajv-formats** (JSON Schema 2020-12) — o schema compartilhado é o contrato com
  o resto do ferramental. Todo achado é validado contra o schema *byte-idêntico* nos testes.
- **regras do gitleaks (vendorizadas, não o binário)** — detecção de segredo é problema
  resolvido; regex à mão é como scanner gera falso negativo. Um subconjunto curado das
  regras open-source do gitleaks (MIT, config na tag **v8.21.2**,
  <https://github.com/gitleaks/gitleaks>) está vendorizado em
  [`src/gitleaks/rules.ts`](./src/gitleaks/rules.ts) como dado. Sem binário, sem fetch.
- **vitest** (só dev) — a suíte é **sem rede**: fixtures de bundle, headers, source maps e
  respostas de `.env`/`.git`, mais uma camada HTTP mock que registra toda requisição.
- **tsx** (só dev) — roda a CLI do fonte sem build.

Dependências de runtime são só `ajv` + `ajv-formats`. O HTTP usa o `fetch` global do Node
(Node 20+); nenhuma dependência de cliente HTTP.

---

## Desenvolvimento

```bash
npm install
npm run build
npm test
npm run typecheck
```

A CI está em [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) (actions fixadas por
SHA, permissões mínimas `contents: read`). **Não foi executada aqui** — roda no push/PR
quando o repo estiver no GitHub.

## Segurança e licença

Ver [`SECURITY.md`](./SECURITY.md). Licença [MIT](./LICENSE), © 2026 Hélio Delfino.
