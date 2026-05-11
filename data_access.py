"""
Camada de acesso a dados usando PostgreSQL (Supabase).

Configure a variável de ambiente DATABASE_URL com a connection string do Supabase:
  postgresql://postgres:<senha>@db.<projeto>.supabase.co:5432/postgres

Localmente: crie um arquivo .env com DATABASE_URL=... e use python-dotenv,
ou exporte a variável antes de rodar: set DATABASE_URL=...
"""
from __future__ import annotations

import json
import logging
import os
import time
import unicodedata
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd
import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

DATABASE_URL = os.environ.get("DATABASE_URL", "")


def _safe_update_dict(data: Dict, allowed_cols: list) -> Dict:
    """Filtra o dict mantendo apenas colunas permitidas (previne SQL injection por nome de coluna)."""
    allowed = set(allowed_cols)
    return {k: v for k, v in data.items() if k in allowed}

# Colunas mantidas para compatibilidade com o restante do app
CLIENT_COLUMNS = [
    "id_cliente", "nome", "cpf_cnpj", "telefone_whatsapp", "email",
    "endereco_rua", "endereco_numero", "endereco_bairro",
    "endereco_cidade", "endereco_uf", "endereco_cep",
    "carro_marca", "carro_modelo", "carro_ano", "carro_placa", "observacoes",
]
VEICULO_COLUMNS = [
    "id_veiculo", "id_cliente", "marca", "modelo", "ano", "placa", "cor", "observacoes",
]
ORCAMENTO_COLUMNS = [
    "id_orcamento", "id_cliente", "id_veiculo", "data_criacao", "status", "carro_km",
    "carro_cor", "responsavel_planejado_id", "responsavel_planejado_nome",
    "itens", "valor_total", "texto_whatsapp", "data_aprovacao",
    "data_conclusao", "forma_pagamento",
]
SERVICO_COLUMNS = [
    "id_servico", "id_orcamento", "id_cliente", "data_execucao",
    "descricao_servico", "tipo_servico", "valor", "observacoes", "responsavel",
]
FINANCEIRO_COLUMNS = [
    "id_lancamento", "data", "tipo_lancamento", "categoria", "descricao",
    "valor", "relacionado_orcamento_id", "relacionado_servico_id",
]
FUNCIONARIOS_COLUMNS = [
    "id_funcionario", "nome", "telefone", "cargo", "observacoes", "ativo",
    "usuario", "senha_hash", "perfil",
]
SOLICITACOES_CADASTRO_COLUMNS = [
    "id_solicitacao", "nome", "telefone", "cargo", "usuario", "senha_hash",
    "status", "data_solicitacao", "data_decisao", "decidido_por",
    "motivo_reprovacao",
]
SECURITY_RATE_LIMIT_COLUMNS = ["rate_key", "fail_count", "blocked_until", "updated_at"]


def _get_conn():
    """Abre uma conexão PostgreSQL. Lança erro claro se DATABASE_URL não estiver configurada."""
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL não configurada. Exporte a variável de ambiente antes de iniciar."
        )
    # Supabase exige SSL; psycopg2 usa sslmode=require por padrão para URLs postgres://
    url = DATABASE_URL
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)


def init_db() -> None:
    """Cria todas as tabelas caso ainda não existam. Chamar uma vez na inicialização."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS clientes (
                    id_cliente      SERIAL PRIMARY KEY,
                    nome            TEXT,
                    cpf_cnpj        TEXT,
                    telefone_whatsapp TEXT,
                    email           TEXT,
                    endereco_rua    TEXT,
                    endereco_numero TEXT,
                    endereco_bairro TEXT,
                    endereco_cidade TEXT,
                    endereco_uf     TEXT,
                    endereco_cep    TEXT,
                    carro_marca     TEXT,
                    carro_modelo    TEXT,
                    carro_ano       TEXT,
                    carro_placa     TEXT,
                    observacoes     TEXT
                )
            """)
            cur.execute("ALTER TABLE clientes ADD COLUMN IF NOT EXISTS cpf_cnpj TEXT")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS veiculos (
                    id_veiculo  SERIAL PRIMARY KEY,
                    id_cliente  INTEGER,
                    marca       TEXT,
                    modelo      TEXT,
                    ano         TEXT,
                    placa       TEXT,
                    cor         TEXT,
                    observacoes TEXT
                )
            """)
            cur.execute("ALTER TABLE veiculos ADD COLUMN IF NOT EXISTS cor TEXT")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orcamentos (
                    id_orcamento               SERIAL PRIMARY KEY,
                    id_cliente                 INTEGER,
                    id_veiculo                 INTEGER,
                    data_criacao               TEXT,
                    status                     TEXT,
                    carro_km                   TEXT,
                    carro_cor                  TEXT,
                    responsavel_planejado_id   TEXT,
                    responsavel_planejado_nome TEXT,
                    itens                      TEXT,
                    valor_total                NUMERIC,
                    texto_whatsapp             TEXT,
                    data_aprovacao             TEXT,
                    data_conclusao             TEXT,
                    forma_pagamento            TEXT
                )
            """)
            # Adiciona id_veiculo em orçamentos antigos (se a coluna ainda não existir)
            cur.execute("""
                ALTER TABLE orcamentos ADD COLUMN IF NOT EXISTS id_veiculo INTEGER
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS servicos (
                    id_servico        SERIAL PRIMARY KEY,
                    id_orcamento      INTEGER,
                    id_cliente        INTEGER,
                    data_execucao     TEXT,
                    descricao_servico TEXT,
                    tipo_servico      TEXT,
                    valor             NUMERIC,
                    observacoes       TEXT,
                    responsavel       TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS financeiro (
                    id_lancamento           SERIAL PRIMARY KEY,
                    data                    TEXT,
                    tipo_lancamento         TEXT,
                    categoria               TEXT,
                    descricao               TEXT,
                    valor                   NUMERIC,
                    relacionado_orcamento_id INTEGER,
                    relacionado_servico_id   INTEGER
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS funcionarios (
                    id_funcionario SERIAL PRIMARY KEY,
                    nome           TEXT,
                    telefone       TEXT,
                    cargo          TEXT,
                    observacoes    TEXT,
                    ativo          TEXT
                )
            """)
            cur.execute("ALTER TABLE funcionarios ADD COLUMN IF NOT EXISTS usuario TEXT")
            cur.execute("ALTER TABLE funcionarios ADD COLUMN IF NOT EXISTS senha_hash TEXT")
            cur.execute("ALTER TABLE funcionarios ADD COLUMN IF NOT EXISTS perfil TEXT")
            cur.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS funcionarios_usuario_unique "
                "ON funcionarios (LOWER(usuario)) WHERE usuario IS NOT NULL AND usuario <> ''"
            )
            cur.execute("""
                CREATE TABLE IF NOT EXISTS solicitacoes_cadastro (
                    id_solicitacao    SERIAL PRIMARY KEY,
                    nome              TEXT,
                    telefone          TEXT,
                    cargo             TEXT,
                    usuario           TEXT,
                    senha_hash        TEXT,
                    status            TEXT DEFAULT 'pendente',
                    data_solicitacao  TIMESTAMP DEFAULT NOW(),
                    data_decisao      TIMESTAMP,
                    decidido_por      TEXT,
                    motivo_reprovacao TEXT
                )
            """)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS solicitacoes_status_idx "
                "ON solicitacoes_cadastro (status)"
            )
            cur.execute("""
                CREATE TABLE IF NOT EXISTS security_rate_limits (
                    rate_key      TEXT PRIMARY KEY,
                    fail_count    INTEGER NOT NULL DEFAULT 0,
                    blocked_until DOUBLE PRECISION NOT NULL DEFAULT 0,
                    updated_at    TIMESTAMP DEFAULT NOW()
                )
            """)
            # Migra carros já cadastrados nos clientes para a tabela veiculos (executa só uma vez)
            cur.execute("""
                INSERT INTO veiculos (id_cliente, marca, modelo, ano, placa)
                SELECT c.id_cliente, c.carro_marca, c.carro_modelo, c.carro_ano, c.carro_placa
                FROM clientes c
                WHERE (
                    (c.carro_marca   IS NOT NULL AND c.carro_marca   <> '')
                    OR (c.carro_modelo IS NOT NULL AND c.carro_modelo <> '')
                    OR (c.carro_placa  IS NOT NULL AND c.carro_placa  <> '')
                )
                AND NOT EXISTS (
                    SELECT 1 FROM veiculos v WHERE v.id_cliente = c.id_cliente
                )
            """)
        conn.commit()
        logger.info("Tabelas verificadas/criadas com sucesso.")
    finally:
        conn.close()


def _rows_to_df(rows, columns: List[str]) -> pd.DataFrame:
    """Converte lista de RealDictRow em DataFrame com as colunas corretas."""
    if not rows:
        return pd.DataFrame(columns=columns)
    df = pd.DataFrame([dict(r) for r in rows])
    for col in columns:
        if col not in df.columns:
            df[col] = None
    return df[columns]


# ---------------------------
# Clientes
# ---------------------------

def get_all_clients() -> pd.DataFrame:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM clientes ORDER BY id_cliente")
            return _rows_to_df(cur.fetchall(), CLIENT_COLUMNS)
    finally:
        conn.close()


def get_client_by_id(client_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM clientes WHERE id_cliente = %s", (client_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def add_client(data: Dict) -> int:
    data.pop("id_cliente", None)
    cols = [c for c in CLIENT_COLUMNS if c != "id_cliente"]
    values = [data.get(c) for c in cols]
    sql = (
        f"INSERT INTO clientes ({', '.join(cols)}) "
        f"VALUES ({', '.join(['%s'] * len(cols))}) RETURNING id_cliente"
    )
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, values)
            new_id = cur.fetchone()["id_cliente"]
        conn.commit()
        return new_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_client(client_id: int, data: Dict) -> bool:
    data.pop("id_cliente", None)
    data = _safe_update_dict(data, [c for c in CLIENT_COLUMNS if c != "id_cliente"])
    if not data:
        return False
    set_clause = ", ".join(f"{k} = %s" for k in data)
    values = list(data.values()) + [client_id]
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE clientes SET {set_clause} WHERE id_cliente = %s",
                values,
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------
# Veículos
# ---------------------------

def get_all_vehicles() -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM veiculos ORDER BY id_cliente, id_veiculo")
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_vehicles_by_client(client_id: int) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM veiculos WHERE id_cliente = %s ORDER BY id_veiculo",
                (client_id,),
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_vehicle_by_id(vehicle_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM veiculos WHERE id_veiculo = %s", (vehicle_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def add_vehicle(data: Dict) -> int:
    data.pop("id_veiculo", None)
    cols = [c for c in VEICULO_COLUMNS if c != "id_veiculo"]
    values = [data.get(c) for c in cols]
    sql = (
        f"INSERT INTO veiculos ({', '.join(cols)}) "
        f"VALUES ({', '.join(['%s'] * len(cols))}) RETURNING id_veiculo"
    )
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, values)
            new_id = cur.fetchone()["id_veiculo"]
        conn.commit()
        return new_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_vehicle(vehicle_id: int, data: Dict) -> bool:
    data.pop("id_veiculo", None)
    data = _safe_update_dict(data, [c for c in VEICULO_COLUMNS if c != "id_veiculo"])
    if not data:
        return False
    set_clause = ", ".join(f"{k} = %s" for k in data)
    values = list(data.values()) + [vehicle_id]
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE veiculos SET {set_clause} WHERE id_veiculo = %s",
                values,
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_vehicle(vehicle_id: int) -> bool:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM veiculos WHERE id_veiculo = %s", (vehicle_id,))
            deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------
# Orçamentos
# ---------------------------

def get_all_budgets() -> pd.DataFrame:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM orcamentos ORDER BY id_orcamento")
            return _rows_to_df(cur.fetchall(), ORCAMENTO_COLUMNS)
    finally:
        conn.close()


def get_budget_by_id(budget_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM orcamentos WHERE id_orcamento = %s", (budget_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def add_budget(data: Dict) -> int:
    data.pop("id_orcamento", None)
    cols = [c for c in ORCAMENTO_COLUMNS if c != "id_orcamento"]
    values = [data.get(c) for c in cols]
    sql = (
        f"INSERT INTO orcamentos ({', '.join(cols)}) "
        f"VALUES ({', '.join(['%s'] * len(cols))}) RETURNING id_orcamento"
    )
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, values)
            new_id = cur.fetchone()["id_orcamento"]
        conn.commit()
        return new_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_budget(budget_id: int, data: Dict) -> bool:
    data.pop("id_orcamento", None)
    data = _safe_update_dict(data, [c for c in ORCAMENTO_COLUMNS if c != "id_orcamento"])
    if not data:
        return False
    set_clause = ", ".join(f"{k} = %s" for k in data)
    values = list(data.values()) + [budget_id]
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE orcamentos SET {set_clause} WHERE id_orcamento = %s",
                values,
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------
# Serviços
# ---------------------------

def get_all_services() -> pd.DataFrame:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM servicos ORDER BY id_servico")
            return _rows_to_df(cur.fetchall(), SERVICO_COLUMNS)
    finally:
        conn.close()


def add_service(data: Dict) -> int:
    data.pop("id_servico", None)
    cols = [c for c in SERVICO_COLUMNS if c != "id_servico"]
    values = [data.get(c) for c in cols]
    sql = (
        f"INSERT INTO servicos ({', '.join(cols)}) "
        f"VALUES ({', '.join(['%s'] * len(cols))}) RETURNING id_servico"
    )
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, values)
            new_id = cur.fetchone()["id_servico"]
        conn.commit()
        return new_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------
# Financeiro
# ---------------------------

def get_all_financial_entries() -> pd.DataFrame:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM financeiro ORDER BY id_lancamento")
            return _rows_to_df(cur.fetchall(), FINANCEIRO_COLUMNS)
    finally:
        conn.close()


def get_financial_entry_by_id(entry_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM financeiro WHERE id_lancamento = %s", (entry_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def add_financial_entry(data: Dict) -> int:
    data.pop("id_lancamento", None)
    for optional_int_col in ("relacionado_orcamento_id", "relacionado_servico_id"):
        if data.get(optional_int_col) == "":
            data[optional_int_col] = None
    cols = [c for c in FINANCEIRO_COLUMNS if c != "id_lancamento"]
    values = [data.get(c) for c in cols]
    sql = (
        f"INSERT INTO financeiro ({', '.join(cols)}) "
        f"VALUES ({', '.join(['%s'] * len(cols))}) RETURNING id_lancamento"
    )
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, values)
            new_id = cur.fetchone()["id_lancamento"]
        conn.commit()
        return new_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_financial_entry(entry_id: int, data: Dict) -> bool:
    data.pop("id_lancamento", None)
    data = _safe_update_dict(data, [c for c in FINANCEIRO_COLUMNS if c != "id_lancamento"])
    for optional_int_col in ("relacionado_orcamento_id", "relacionado_servico_id"):
        if data.get(optional_int_col) == "":
            data[optional_int_col] = None
    if not data:
        return False
    set_clause = ", ".join(f"{k} = %s" for k in data)
    values = list(data.values()) + [entry_id]
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE financeiro SET {set_clause} WHERE id_lancamento = %s",
                values,
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_financial_entry(entry_id: int) -> bool:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM financeiro WHERE id_lancamento = %s", (entry_id,))
            deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------
# Funcionários
# ---------------------------

def get_all_employees() -> pd.DataFrame:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM funcionarios ORDER BY id_funcionario")
            return _rows_to_df(cur.fetchall(), FUNCIONARIOS_COLUMNS)
    finally:
        conn.close()


def get_employee_by_id(employee_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM funcionarios WHERE id_funcionario = %s", (employee_id,)
            )
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def get_employee_by_username(usuario: str) -> Optional[Dict]:
    """Busca um funcionário pelo nome de usuário (case-insensitive)."""
    if not usuario:
        return None
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM funcionarios "
                "WHERE usuario IS NOT NULL AND LOWER(usuario) = LOWER(%s) "
                "LIMIT 1",
                (usuario.strip(),),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def add_employee(data: Dict) -> int:
    data.pop("id_funcionario", None)
    cols = [c for c in FUNCIONARIOS_COLUMNS if c != "id_funcionario"]
    values = [data.get(c) for c in cols]
    sql = (
        f"INSERT INTO funcionarios ({', '.join(cols)}) "
        f"VALUES ({', '.join(['%s'] * len(cols))}) RETURNING id_funcionario"
    )
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, values)
            new_id = cur.fetchone()["id_funcionario"]
        conn.commit()
        return new_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_employee(employee_id: int, data: Dict) -> bool:
    data.pop("id_funcionario", None)
    data = _safe_update_dict(data, [c for c in FUNCIONARIOS_COLUMNS if c != "id_funcionario"])
    if not data:
        return False
    set_clause = ", ".join(f"{k} = %s" for k in data)
    values = list(data.values()) + [employee_id]
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE funcionarios SET {set_clause} WHERE id_funcionario = %s",
                values,
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def deduplicate_employees() -> int:
    """Remove duplicatas de funcionários com o mesmo nome, mantendo o registro ativo de menor id.
    Retorna o número de registros removidos."""
    df = get_all_employees().fillna("")
    if df.empty:
        return 0

    inactive_values = {"false", "0", "nao", "não"}

    def _normalize_name(value: str) -> str:
        normalized = unicodedata.normalize("NFKD", str(value or ""))
        normalized = "".join(ch for ch in normalized if not unicodedata.combining(ch))
        return " ".join(normalized.casefold().split())

    df["_nome_norm"] = df["nome"].astype(str).apply(_normalize_name)
    df["_is_ativo"] = ~df["ativo"].astype(str).str.strip().str.lower().isin(inactive_values)

    ids_to_delete = []
    for _, grupo in df.groupby("_nome_norm"):
        if len(grupo) <= 1:
            continue
        ativos = grupo[grupo["_is_ativo"]]
        keeper = ativos.sort_values("id_funcionario").iloc[0] if not ativos.empty else grupo.sort_values("id_funcionario").iloc[0]
        ids_to_delete.extend(
            int(row["id_funcionario"])
            for _, row in grupo.iterrows()
            if int(row["id_funcionario"]) != int(keeper["id_funcionario"])
        )

    if not ids_to_delete:
        return 0

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"DELETE FROM funcionarios WHERE id_funcionario = ANY(%s)",
                (ids_to_delete,),
            )
            deleted = cur.rowcount
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------
# Rate limit de segurança
# ---------------------------

def get_rate_limit_state(rate_key: str) -> Optional[Dict]:
    if not rate_key:
        return None
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT rate_key, fail_count AS count, blocked_until, updated_at "
                "FROM security_rate_limits WHERE rate_key = %s",
                (rate_key,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def clear_rate_limit_state(rate_key: str) -> None:
    if not rate_key:
        return
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM security_rate_limits WHERE rate_key = %s", (rate_key,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def record_rate_limit_failure(rate_key: str, max_attempts: int, block_seconds: int) -> Dict:
    """Registra falha em tabela compartilhada entre workers."""
    if not rate_key:
        return {"count": 0, "blocked_until": 0.0}
    now = time.time()
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT fail_count, blocked_until FROM security_rate_limits "
                "WHERE rate_key = %s FOR UPDATE",
                (rate_key,),
            )
            row = cur.fetchone()
            if row and float(row.get("blocked_until") or 0) > now:
                count = int(row.get("fail_count") or 0)
                blocked_until = float(row.get("blocked_until") or 0)
            else:
                previous_count = int(row.get("fail_count") or 0) if row else 0
                if row and previous_count >= max_attempts:
                    previous_count = 0
                count = previous_count + 1
                blocked_until = now + block_seconds if count >= max_attempts else 0.0

            cur.execute(
                """
                INSERT INTO security_rate_limits (rate_key, fail_count, blocked_until, updated_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (rate_key) DO UPDATE SET
                    fail_count = EXCLUDED.fail_count,
                    blocked_until = EXCLUDED.blocked_until,
                    updated_at = NOW()
                """,
                (rate_key, count, blocked_until),
            )
        conn.commit()
        return {"count": count, "blocked_until": blocked_until}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------
# Solicitações de cadastro
# ---------------------------

def add_signup_request(data: Dict) -> int:
    """Insere uma nova solicitação de cadastro com status 'pendente'."""
    cols = ["nome", "telefone", "cargo", "usuario", "senha_hash"]
    values = [data.get(c) for c in cols]
    sql = (
        f"INSERT INTO solicitacoes_cadastro ({', '.join(cols)}, status) "
        f"VALUES ({', '.join(['%s'] * len(cols))}, 'pendente') "
        "RETURNING id_solicitacao"
    )
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, values)
            new_id = cur.fetchone()["id_solicitacao"]
        conn.commit()
        return new_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_signup_requests(status: Optional[str] = None) -> List[Dict]:
    """Lista solicitações; se status for informado, filtra por ele."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            if status:
                cur.execute(
                    "SELECT * FROM solicitacoes_cadastro WHERE status = %s "
                    "ORDER BY data_solicitacao DESC",
                    (status,),
                )
            else:
                cur.execute(
                    "SELECT * FROM solicitacoes_cadastro "
                    "ORDER BY data_solicitacao DESC"
                )
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_signup_request_by_id(request_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM solicitacoes_cadastro WHERE id_solicitacao = %s",
                (request_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def count_pending_signup_requests() -> int:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS total FROM solicitacoes_cadastro WHERE status = 'pendente'"
            )
            row = cur.fetchone()
            return int(row["total"]) if row else 0
    finally:
        conn.close()


def has_pending_signup_for_username(usuario: str) -> bool:
    if not usuario:
        return False
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM solicitacoes_cadastro "
                "WHERE status = 'pendente' AND LOWER(usuario) = LOWER(%s) LIMIT 1",
                (usuario.strip(),),
            )
            return cur.fetchone() is not None
    finally:
        conn.close()


def mark_signup_request_decision(
    request_id: int, status: str, decided_by: str, motivo: Optional[str] = None
) -> bool:
    """Atualiza status, decidido_por, data_decisao e motivo (quando reprovada)."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE solicitacoes_cadastro "
                "SET status = %s, decidido_por = %s, data_decisao = NOW(), "
                "    motivo_reprovacao = %s "
                "WHERE id_solicitacao = %s",
                (status, decided_by, motivo, request_id),
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------
# Utilitários (mantidos idênticos)
# ---------------------------

def ensure_all_files_exist() -> None:
    """Compatibilidade: agora inicializa o banco em vez de criar arquivos."""
    init_db()


def get_data_files() -> Dict[str, str]:
    return {}


def parse_budget_items(items_json: str) -> List[Dict]:
    if not items_json:
        return []
    try:
        return json.loads(items_json)
    except json.JSONDecodeError:
        return []


def serialize_budget_items(items: List[Dict]) -> str:
    return json.dumps(items, ensure_ascii=False)


def format_currency(value: float) -> str:
    try:
        return f"R$ {float(value):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except (TypeError, ValueError):
        return "R$ 0,00"


def month_boundaries(date: datetime) -> Dict[str, datetime]:
    first_day = date.replace(day=1)
    if date.month == 12:
        next_month = date.replace(year=date.year + 1, month=1, day=1)
    else:
        next_month = date.replace(month=date.month + 1, day=1)
    last_day = next_month - pd.Timedelta(days=1)
    return {"start": first_day, "end": last_day}
