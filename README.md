# acr-audit

Audita imagens no Azure Container Registry e reporta quais **não têm as labels obrigatórias** de governança — ou seja, quem fez `FROM` fora do pipeline Base Images.

## Como funciona

Labels OCI (`LABEL` no Dockerfile) são herdadas via `FROM`. Imagens produzidas pelo Base Images têm um conjunto conhecido de labels; derivadas as herdam; quem puxou de `registry.redhat.io` direto não tem.

## Requisitos

- Python 3.10+
- `az` CLI logado (`az login`) com permissão de pull no ACR
- Para dev: `pip install pytest ruff` (ou já disponíveis no PATH)

## Setup

Nada a compilar. O `audit.py` é stdlib pura.

```bash
make check   # lint + 80 testes de regressão
```

## Uso

```bash
python3 audit.py \
  --acr <nome-ou-fqdn> \
  --label com.empresa.base-image \
  --label com.empresa.pipeline=governed \
  --exclude-repo 'base-images/*' \
  --top 10 \
  --output report.json \
  --fail-on-violation
```

### Flags

| Flag | Descrição |
|---|---|
| `--acr` (obrigatório) | `acme` ou `acme.azurecr.io` |
| `--label KEY[=VALUE]` (obrigatório, repetível) | Label exigida. `KEY` só exige existência; `KEY=VALUE` exige valor exato |
| `--exclude-repo GLOB` (repetível) | Repos a ignorar (ex.: `base-images/*`) |
| `--include-repo GLOB` (repetível) | Restringe o escopo (default: tudo) |
| `--top N` | N imagens **com tag** mais recentes por repo (padrão: 10). Manifests sem tag — scans do Defender, SBOM, órfãos — são ignorados |
| `--platform os/arch` | Plataforma em image index multi-arch (padrão: `linux/amd64`) |
| `--workers N` | Threads paralelas (padrão: 16) |
| `--output FILE` | Caminho do JSON (padrão: `audit-report.json`) |
| `--fail-on-violation` | Exit 1 se houver violação (útil em CI) |

## Saída (JSON)

```json
{
  "scan": {
    "acr": "acme.azurecr.io",
    "scanned_at": "2026-11-27T13:14:51+00:00",
    "duration_s": 0.0,
    "repos_total": 2,
    "repos_scanned": 2,
    "images_scanned": 3,
    "violations_count": 3,
    "errors_count": 0,
    "required_labels": ["com.empresa.base-image", "com.empresa.pipeline=governed"],
    "excluded_repos": ["base-images/*"],
    "top_per_repo": 10,
    "platform": "linux/amd64"
  },
  "violations": [
    {
      "repo": "teamy/legacy",
      "tags": ["old"],
      "digest": "sha256:legacy",
      "pushed_at": "2024-01-01T00:00:00Z",
      "missing_labels": ["com.empresa.base-image", "com.empresa.pipeline"]
    }
  ],
  "errors": []
}
```

## Estrutura

```
audit.py                 # CLI + orquestração
acr_audit/
  auth.py                # az login → tokens ACR (cache thread-safe)
  client.py              # HTTP (retry + paginação Link header)
  registry.py            # catálogo, manifests, resolve multi-arch
  rules.py               # parsing e checagem de labels
  report.py              # JSON writer
tests/                   # 80 testes de regressão (sem rede)
```

## Testes

```bash
make test      # pytest
make lint      # ruff check + format --check
make check     # ambos (CI local)
make format    # aplica fix + format
```
