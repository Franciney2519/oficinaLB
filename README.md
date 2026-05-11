# Oficina Mecanica - LB AUTOCAR

Aplicacao web em Flask para gestao de oficina mecanica: clientes, veiculos, orcamentos, servicos, financeiro e funcionarios.  
Banco de dados: PostgreSQL (Supabase).

## Funcionalidades

- Clientes com multiplos veiculos.
- Edicao de cliente, inclusao/edicao/exclusao de veiculos.
- Migracao de veiculo legado para veiculo editavel.
- Orcamentos com itens dinamicos e forma de pagamento.
- Taxa de 3% em Cartao Credito.
- PDF de orcamento e recibo.
- Texto pronto para WhatsApp.
- Financeiro com entradas/saidas.
- Dashboard com saldo por periodo e grafico dos ultimos 12 meses.

## Regras de negocio importantes

- Entrada no financeiro e criada quando o orcamento e concluido/efetivado.
- Orcamento apenas aprovado (sem conclusao) nao gera entrada no saldo.
- Sistema evita duplicidade na efetivacao:
  - nao duplica servicos do mesmo orcamento;
  - nao duplica entrada financeira do mesmo orcamento.
- Orcamento finalizado pode ser editado para correcao de preenchimento.
- Orcamentos reprovados aparecem com destaque visual em vermelho na listagem.
- Cadastro de cliente sem nome e bloqueado.

## Fluxo de status de orcamento

- Em analise -> Aprovado -> Concluido
- Em analise -> Reprovado

Obs.: no estado Concluido, o sistema registra execucao de servico e entrada no financeiro.

## Requisitos

- Python 3.10+
- PostgreSQL

Dependencias principais:

- flask
- pandas
- psycopg2-binary
- fpdf2
- gunicorn
- python-dotenv
- pillow (opcional)

## Configuracao local

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Crie `.env` na raiz:

```env
DATABASE_URL=postgresql://usuario:senha@host:5432/postgres
SECRET_KEY=sua-chave-secreta
APP_USERNAME=admin
APP_PASSWORD=sua-senha
```

Rodar:

```bash
python app.py
```

## Variaveis de ambiente

| Variavel | Padrao | Descricao |
|---|---|---|
| `DATABASE_URL` | - | String de conexao PostgreSQL (obrigatoria) |
| `SECRET_KEY` | `oficina-mecanica-secret-dev` | Chave de sessao Flask |
| `APP_USERNAME` | `admin` | Usuario de login |
| `APP_PASSWORD` | `oficina123` | Senha de login |

## Banco de dados

Tabelas principais:

- `clientes`
- `veiculos`
- `orcamentos`
- `servicos`
- `financeiro`
- `funcionarios`

As tabelas sao criadas/ajustadas na inicializacao via `data_access.py`.

## Seguranca Supabase (RLS)

Quando necessario, gere SQL de hardening com:

```bash
python exportar_seguranca_supabase.py --csv "c:\caminho\arquivo.csv" --out supabase_security_hardening.sql
```

Depois execute o SQL no Supabase SQL Editor.

## Deploy

`Procfile`:

```txt
web: gunicorn app:app
```

`ProxyFix` ja esta habilitado para ambiente com proxy (Railway/Render).

## Estrutura

```txt
app.py
data_access.py
templates/
static/
```
