# Checkup do repositório `awscurl`

Branch analisada: `claude/repo-checkup-review-EPd3L`
HEAD: `89c74fa` (Bump version to 0.42 — add README as PyPI long_description)
Data: 2026-05-18

Sem commits / push / interação com GitHub feitos. Este documento é só leitura: lista vulnerabilidades, bugs, riscos e melhorias encontradas, com referência a arquivo:linha. Use-o como cardápio — depois você me diz o que atacar.

## Sumário executivo

| Severidade | Quantos | Categoria |
| --- | --- | --- |
| Alta | 4 | credenciais commitadas, log de credenciais em verbose, header SigV4 inconsistente (token vazio assinado/não assinado), `requirements.txt` sem pin |
| Média | 8 | bugs de parsing (`split("=")`, `split(": ")`), `load_aws_config` com `while/break` quebrado, `utcnow()` deprecado, `-o` sempre duplica saída, publish via `setup.py sdist` deprecado, Docker login por senha, deps duplicadas no `setup.py`, falta `python_requires` |
| Baixa | 7+ | imports duplicados, `pyrightconfig.json` órfão, `__log` usa `pprint`, `boto3` em `install_requires` sem uso direto, dockerfile alpine sem digest, MANIFEST.in ausente, validação `tls_min/max` só com ambos definidos |

Status atual da suíte:
- `pycodestyle awscurl` ✅
- `mypy awscurl/ tests/` ✅ (`Success: no issues found in 12 source files`)
- `pytest` offline (unit + stages + url_parsing + load_aws_config + basic) ✅ 23/23
- `tests/integration_test.py` e `tests/tls_test.py::TestHTTPSDefaultTLS` exigem rede + creds reais (S3).

---

## 1. Vulnerabilidades de segurança

### 1.1 [ALTA] Credenciais AWS reais commitadas em `tests/integration_test.py`
Linhas 33-34, 56-57, 79-80, 102-103 — duas strings base64 que decodificam para um Access Key ID válido (formato `AKIA…`, 20 chars) + um Secret Access Key de 40 chars. As strings exatas estão no arquivo de teste; este documento intencionalmente não as reproduz para não disparar push-protection.

Mesmo que sejam read-only para um bucket público, o padrão é tóxico:
- Scanners (GitHub secret scanning, gitleaks, AWS GuardDuty) sinalizam — base64 dribla parte deles mas não todos.
- Quem fizer fork passa a "possuir" essas chaves no histórico.
- A AGENTS.md diz "Never log or expose AWS credentials" — esse padrão contraria a própria diretriz do projeto.

**Sugestão:** usar `pytest.mark.skipif` quando credenciais reais não estiverem disponíveis e ler de env vars (`AWS_ACCESS_KEY_ID` etc.) ou de um perfil; rotacionar as chaves no IAM da AWS.

### 1.2 [ALTA] `--verbose` vaza `access_key`/`secret_key`/tokens em stderr
`awscurl/awscurl.py:608-609`:

```python
if args.verbose:
    __log(vars(args))
```

`vars(args)` contém `access_key`, `secret_key`, `security_token`, `session_token`. AGENTS.md explicitamente proíbe ("Never log or expose AWS credentials — check `__log`, error paths, and `load_aws_config`"). Reproduz com `awscurl -v --access_key AKIA... ...` → stderr mostra a chave.

**Sugestão:** redigir antes de logar (substituir os 4 campos por `***` numa cópia de `vars(args)`).

### 1.3 [ALTA] Header `x-amz-security-token` enviado mas NÃO assinado quando token = `""`
`awscurl/awscurl.py:243-244` (task_1) usa truthiness:

```python
if security_token:
    canonical_headers_dict['x-amz-security-token'] = security_token
```

`awscurl/awscurl.py:371-372` (task_4) usa `is not None`:

```python
if security_token is not None:
    headers['x-amz-security-token'] = security_token
```

Resultado com `security_token=""`: header sai no request mas não entra no canonical / `signed_headers`. AWS rejeita por SigV4 mismatch quando há um `x-amz-*` não assinado. O teste `tests/unit_test.py::TestMakeRequest::test_make_request` (linhas 90-95) congela esse bug como comportamento esperado (`'x-amz-security-token': ''` no expected).

**Sugestão:** alinhar ambos para `if security_token:` (ou `is not None` com normalização para `None` em `normalize_args`), atualizar testes.

### 1.4 [ALTA] `requirements.txt` sem pinning de versão
`requirements.txt` lista `requests`, `configargparse`, `configparser`, `botocore` sem `==` nem `>=`. CI pega "latest" a cada execução — supply-chain weak point e CI flake. `setup.py` também tem `install_requires` sem pin.

**Sugestão:** pinar versões mínimas testadas (`requests>=2.32,<3`, etc.) e considerar `pip-compile` para gerar `requirements.lock`.

### 1.5 [MÉDIA] Docker Hub login com senha (`DOCKER_PASSWORD`)
`.github/workflows/dockerhubpublish.yml:14`. Docker Hub recomenda **access tokens** (`DOCKER_TOKEN`) com escopo restrito; senha dá acesso total à conta.

### 1.6 [MÉDIA] PyPI publish com user/senha (`TWINE_USERNAME`/`TWINE_PASSWORD`)
`.github/workflows/pythonpublish.yml:21-22`. PyPI hoje obriga 2FA — recomenda **trusted publishing (OIDC)** ou pelo menos `TWINE_USERNAME=__token__` + token de projeto.

### 1.7 [MÉDIA] `_TLSAdapter` desativa verificação de hostname e CN quando `--insecure`
`awscurl/awscurl.py:430-432` — comportamento intencional (curl `-k` faz o mesmo). Mas é importante garantir que `--insecure` continue exclusivo a essa flag e nunca seja default; OK pelo código atual, vale uma nota.

### 1.8 [BAIXA] Dockerfile não pina digest da imagem base
`Dockerfile:2`/`19`: `python:3-alpine`. Build reprodutível e seguro exigem `python:3.13.3-alpine@sha256:...`. Idem para os Dockerfiles em `ci/ci-*/Dockerfile`.

### 1.9 [BAIXA] CI Dockerfiles instalam pyenv via `curl | bash`
`ci/ci-*/Dockerfile`: `RUN curl https://pyenv.run | bash`. Roda código remoto não verificado em build de CI; risco de supply chain. Fora do hot path (só CI manual), mas vale conhecer.

---

## 2. Bugs funcionais

### 2.1 [MÉDIA] `__normalize_query_string` quebra valores com `=` no meio
`awscurl/awscurl.py:384-391`:

```python
parameter_pairs = (list(map(str.strip, s.split("=")))
                   for s in query.split('&') if len(s) > 0)
normalized = '&'.join('%s=%s' % (aws_url_encode(p[0]), aws_url_encode(p[1]) if len(p) > 1 else '')
                      for p in sorted(parameter_pairs))
```

Para `?token=abc=def`, `split("=")` → `['token','abc','def']`; só `p[0]`/`p[1]` são usados → vira `token=abc`, perdendo `=def`. Deveria ser `s.split("=", 1)`. Também o `str.strip` em valores muda assinatura para queries que legitimamente contenham espaço (improvável, mas a especificação SigV4 não pede strip de valor).

### 2.2 [MÉDIA] `load_aws_config` para no primeiro campo faltante
`awscurl/awscurl.py:480-494`:

```python
while True:
    if access_key is None and config.has_option(profile, "aws_access_key_id"):
        access_key = config.get(profile, "aws_access_key_id")
    else:
        break
    if secret_key is None and config.has_option(profile, "aws_secret_access_key"):
        ...
```

Se quem chama já passa `access_key` mas não `secret_key`, a primeira condição cai no `else: break` e `secret_key` nunca é lido do arquivo. O `while True` aqui é "if-em-disfarce" e a lógica de short-circuit está invertida. Reescrever sem o loop, lendo cada campo independentemente.

### 2.3 [MÉDIA] Parse de header com mais de um `": "` levanta exceção
`awscurl/awscurl.py:623`:

```python
headers = {k: v for (k, v) in map(lambda s: s.split(": "), args.header)}
```

`-H "Authorization: Bearer foo: bar"` → `split(": ")` produz 3 itens → `ValueError: too many values to unpack`. Usar `s.split(": ", 1)`.

### 2.4 [MÉDIA] `-o`/`--output` sempre duplica saída em stdout
`awscurl/awscurl.py:660-669`: `print(response.text)` roda sempre; só depois é que `args.output` grava arquivo. No curl, `-o file` redireciona — não duplica. Hoje saída vai para stdout E para o arquivo.

### 2.5 [MÉDIA] `--data-binary` controla o modo de escrita do `--output`
`awscurl/awscurl.py:663-669`: o modo de gravação (`"wb"` vs `"w"`) depende de `args.data_binary`, mas `data_binary` é flag do **request**, não da **resposta**. Quem envia JSON e recebe binário fica com arquivo corrompido. Decisão deveria vir de algo como `--output-binary` ou sempre `"wb"` com `response.content`.

### 2.6 [MÉDIA] `make_request` sempre chama `datetime.utcnow()` (deprecado)
`awscurl/awscurl.py:407-408`:

```python
def __now():
    return datetime.datetime.utcnow()
```

`utcnow()` está marcado como deprecated no Python 3.12+ (devolve naive datetime). Trocar por `datetime.datetime.now(datetime.timezone.utc)`. Não quebra hoje, mas vai gerar `DeprecationWarning` e algum dia será removido. CI já roda 3.13 (`.python-version`).

### 2.7 [MÉDIA] `--tls-min`/`--tls-max` só valida ordem se ambos forem passados
`awscurl/awscurl.py:448-452`: `if tls_min is not None and tls_max is not None`. Pedido só `--tls-min 1.3` com sistema cuja `maximum_version` é 1.2 vai falhar no handshake sem mensagem clara. Validação simples: comparar contra os limites suportados pelo Python/openssl.

### 2.8 [MÉDIA] `--access_key`/`--secret_key`/`--security_token`/`--session_token` quebram convenção curl
README e AGENTS dizem "siga a convenção do curl". O resto das flags usa hífen (`--data-binary`, `--fail-with-body`, `--tls-min`), mas essas quatro usam underscore. Manter aliases (`--access-key` + `--access_key`) com `dest=` resolveria sem quebrar backward compat.

### 2.9 [BAIXA] `import urllib` + `from urllib.parse import quote` redundantes
`awscurl/awscurl.py:21-22`. Já existe `urllib.parse.urlparse` na linha 230; pode-se reduzir para `from urllib.parse import urlparse, quote`.

### 2.10 [BAIXA] `from typing import Dict` duplicado
`awscurl/awscurl.py:7` e `:20`. mypy aceita, pycodestyle não pega, mas é ruído.

### 2.11 [BAIXA] `url_path_to_dict` faz regex próprio em vez de `urllib.parse.urlparse`
`awscurl/awscurl.py:54-75`. O regex é frágil (e o comentário admite: copiado do StackOverflow). `urlparse` cobre os casos testados; mantê-lo encoberto pelos testes está OK mas vale a refatoração.

### 2.12 [BAIXA] `botocore` import "opcional" é dead code
`awscurl/awscurl.py:509-519`: `try: import botocore` num `try/except ImportError`, mas `botocore` já é import top-level obrigatório na linha 18. Sempre cai no caminho feliz; o `except ImportError` é inalcançável.

### 2.13 [BAIXA] `credentials_path` monta path com `+ "/.aws/credentials"`
`awscurl/awscurl.py:626`. Quebra em Windows; usar `os.path.join(os.path.expanduser("~"), ".aws", "credentials")` ou `pathlib.Path.home() / ".aws" / "credentials"`.

---

## 3. Dependências / packaging

### 3.1 [MÉDIA] `setup.py:36` lista `configparser` (backport de Py2) — supérfluo em Py3
`configparser` é stdlib desde Py3.0. Manter força usuários a baixar um pacote inútil.

### 3.2 [MÉDIA] `setup.py:39` lista `boto3` em `install_requires` sem uso
O código importa só `botocore` (`from botocore import crt, awsrequest` etc.). `boto3` arrasta s3transfer + dependências grandes (~10MB extra). Remover.

### 3.3 [MÉDIA] `setup.py` sem `python_requires`
CI testa Py 3.10/3.11/3.12/3.13, mas o pacote permite `pip install` em qualquer versão. Tipagem `dict[str, str]` em `tests/unit_test.py:77` quebra em <3.9. Adicionar `python_requires=">=3.10"`.

### 3.4 [BAIXA] `MANIFEST.in` inexistente apesar de `setup.py` ler `README.md` para long_description
`setup.py:9-10` faz `open("README.md")` em build time. setuptools moderno inclui README.md por padrão no sdist, mas é frágil; adicionar `MANIFEST.in` com `include README.md LICENSE` previne quebra de instalação por sdist.

### 3.5 [BAIXA] Publish workflow ainda usa `python setup.py sdist bdist_wheel`
`scripts/pypi_publish.sh:5` e `.github/workflows/pythonpublish.yml:23`. setuptools deprecou o uso direto; usar `python -m build`.

### 3.6 [BAIXA] `pyrightconfig.json` órfão
Arquivo existe mas nenhum step de CI roda pyright (só `mypy`). Ou usar (substituir `mypy` por `pyright` em `pythonapp.yml`) ou remover.

---

## 4. CI/CD

### 4.1 Matriz redundante
`pythonapp.yml`: roda `ubuntu-22.04`, `ubuntu-24.04`, `ubuntu-latest` em paralelo. `ubuntu-latest` hoje é `24.04` (vai virar `26.04` em algum momento). Tem teste duplicado. Manter `ubuntu-22.04` + `ubuntu-latest` cobre o útil.

### 4.2 Sem cache de pip
Nenhum step usa `actions/setup-python` com `cache: pip`. Cada job baixa dependências do zero (~4 jobs * 4 Python versions = 16 instalações). Adicionar `cache: pip` corta minutos de CI.

### 4.3 `--cov-fail-under=77` é baixo demais
Coverage gate é 77%. Vale checar onde está o gap (provavelmente `load_aws_config` e ramos de erro). Subir progressivamente.

### 4.4 Workflows sem `permissions:` mínimo
Nenhum YAML define `permissions:` — runs herdam o default do repo. Boa prática é `permissions: contents: read` no topo e elevar por job (e.g. `packages: write` só onde publica imagem).

### 4.5 Sem job de lint dedicado para o Dockerfile
`hadolint` seria útil; o `Dockerfile` atual tem `pip install --user botocore` no estágio builder (linha 11) que é redundante com o `pip install /app-source-dir` da linha 15.

---

## 5. Documentação / governança

- `README.md` lista opções em uma seção "Options" copiada à mão; já desatualizou (não menciona `--tls-min`/`--tls-max`). Gerar via `argparse-manpage` ou similar evita drift.
- `DEVELOP.md` tem 11 linhas; instruções de venv local estão escondidas no `Makefile`. Unir.
- `.github/PULL_REQUEST_TEMPLATE.md` não foi auditado aqui, mas vale conferir se pede checklist de testes.
- Não há `SECURITY.md` orientando como reportar CVE — adicionar.
- Não há `CHANGELOG.md`; releases ficam só no GitHub.

---

## 6. Lista priorizada (para discutir o que atacar primeiro)

1. **Tirar chaves AWS dos testes** (§1.1) — fix isolado em `tests/integration_test.py`, requer rotação na AWS.
2. **Não logar credenciais em `--verbose`** (§1.2) — patch de ~5 linhas em `inner_main`.
3. **Consertar `x-amz-security-token` inconsistente** (§1.3) — afeta SigV4 com token vazio; testes precisam ajustar.
4. **Pinar deps mínimas em `requirements.txt` + `setup.py`** (§1.4, §3.1, §3.2, §3.3).
5. **Fix de parsing** (§2.1, §2.3) — bugs sutis com payloads reais.
6. **`load_aws_config` while/break invertido** (§2.2).
7. **Comportamento de `-o`** (§2.4, §2.5).
8. **`utcnow()` deprecation** (§2.6).
9. **CI permissions/cache/matrix** (§4.x).
10. **Limpeza/refactor** (§2.9-2.13, §3.5, §3.6).

---

## 7. Como verifiquei

- Leitura integral de: `awscurl/{awscurl.py,utils.py,__main__.py,__init__.py}`, `setup.py`, `setup.cfg`, `requirements*.txt`, `Dockerfile`, `Makefile`, `scripts/*`, `tests/*`, `.github/workflows/*`, `.github/{dependabot.yml,CODEOWNERS,copilot-instructions.md}`, `ci/*/Dockerfile`.
- `pycodestyle -v awscurl` → 0 issues.
- `mypy awscurl/ tests/` → 0 issues.
- `pytest` offline (excluindo `integration_test.py` e `tls_test.py::TestHTTPSDefaultTLS`) → 23 passed.
- Decodificação fora-da-árvore das strings base64 em `integration_test.py` para confirmar que os bytes formam um access key + secret válidos no formato AWS (não reproduzidos aqui).
- Histórico de commits via `git log --oneline -20` para entender baseline e PRs recentes (#235, #232-#234).
