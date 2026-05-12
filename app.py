"""
Aplicação Flask para gestão de oficina mecânica.

Desenvolvimento local:
    1. Copie .env.example para .env e preencha DATABASE_URL (Supabase).
    2. pip install -r requirements.txt
    3. python app.py

Produção (Railway / Render):
    - Configure DATABASE_URL e SECRET_KEY nas variáveis de ambiente da plataforma.
    - O Procfile já configura o gunicorn automaticamente.
"""
from __future__ import annotations

import json
import hmac
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import quote, urljoin, urlparse

# Carrega variáveis do .env em desenvolvimento local
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
import math
import unicodedata
import webbrowser
from threading import Timer
from typing import List, Tuple, Optional
from io import BytesIO

try:
    import pandas as pd
except ImportError as exc:  # Segurança: caso pandas não esteja disponível ainda
    raise RuntimeError(
        "Instale as dependências com 'pip install flask pandas openpyxl'"
    ) from exc

from functools import wraps

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
    send_file,
    session,
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from fpdf import FPDF

try:
    from PIL import Image
except ImportError:  # pillow is opcional; ícone será pulado se não estiver disponível
    Image = None

import data_access as dal


def _resolve_base_dir() -> str:
    """Determina a raiz do bundle (suporta execução congelada/onedir do PyInstaller)."""
    base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    internal_dir = os.path.join(base_dir, "_internal")
    if not os.path.exists(os.path.join(base_dir, "templates")) and os.path.exists(
        os.path.join(internal_dir, "templates")
    ):
        return internal_dir
    return base_dir


PROJECT_DIR = _resolve_base_dir()

app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_DIR, "templates"),
    static_folder=os.path.join(PROJECT_DIR, "static"),
)
# Necessário para que Flask reconheça HTTPS quando atrás do proxy do Railway
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

_IS_PRODUCTION = (
    os.environ.get("FLASK_ENV") == "production"
    or bool(os.environ.get("RAILWAY_ENVIRONMENT"))
    or bool(os.environ.get("RENDER"))
)

app.secret_key = os.environ.get("SECRET_KEY", "oficina-mecanica-secret-dev")
if _IS_PRODUCTION and app.secret_key == "oficina-mecanica-secret-dev":
    raise RuntimeError("Configure a variável SECRET_KEY antes de iniciar em produção.")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = _IS_PRODUCTION
app.config["WTF_CSRF_TIME_LIMIT"] = None  # token vale enquanto sessão durar

csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    app.logger.warning("CSRF bloqueado em %s: %s", request.path, error.description)
    flash("Sessao expirada ou formulario invalido. Recarregue a pagina e tente novamente.", "danger")
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    if session.get("role") == ROLE_ADMIN:
        return redirect(url_for("dashboard"))
    return redirect(url_for("meus_servicos"))

_DEFAULT_APP_USERNAME = "admin"
_DEFAULT_APP_PASSWORD = "oficina123"
APP_USERNAME = (os.environ.get("APP_USERNAME") or "").strip()
APP_PASSWORD = os.environ.get("APP_PASSWORD") or ""
_FALLBACK_ADMIN_ENABLED = bool(APP_USERNAME and APP_PASSWORD)

if _FALLBACK_ADMIN_ENABLED and (
    APP_USERNAME == _DEFAULT_APP_USERNAME or APP_PASSWORD == _DEFAULT_APP_PASSWORD
):
    fallback_message = (
        "APP_USERNAME/APP_PASSWORD usam defaults inseguros. "
        "Configure credenciais fortes ou remova essas variaveis para desabilitar o fallback."
    )
    if _IS_PRODUCTION:
        raise RuntimeError(fallback_message)
    app.logger.warning("%s Fallback admin desabilitado.", fallback_message)
    APP_USERNAME = ""
    APP_PASSWORD = ""
    _FALLBACK_ADMIN_ENABLED = False

ROLE_ADMIN = "admin"
ROLE_MECANICO = "mecanico"
VALID_ROLES = {ROLE_ADMIN, ROLE_MECANICO}

_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_BLOCK_SECONDS = 300  # 5 minutos
_SIGNUP_MAX_ATTEMPTS = 5
_SIGNUP_BLOCK_SECONDS = 600  # 10 minutos
_local_rate_failures: dict = {}  # fallback local se o banco estiver indisponivel


def _normalize_role(value) -> str:
    """Garante que o perfil salvo seja um valor válido; default: mecânico."""
    if not value:
        return ROLE_MECANICO
    norm = str(value).strip().lower()
    return norm if norm in VALID_ROLES else ROLE_MECANICO


def require_admin(view):
    """Bloqueia rotas restritas ao perfil administrador."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != ROLE_ADMIN:
            flash("Acesso restrito ao administrador.", "danger")
            return redirect(url_for("meus_servicos"))
        return view(*args, **kwargs)
    return wrapped


def _safe_redirect_from_referrer(default_endpoint: str):
    """Redireciona apenas para referrers do mesmo host."""
    referrer = request.referrer
    if referrer:
        host_url = urlparse(request.host_url)
        target_url = urlparse(urljoin(request.host_url, referrer))
        if target_url.scheme in {"http", "https"} and target_url.netloc == host_url.netloc:
            return redirect(referrer)
    return redirect(url_for(default_endpoint))


def _get_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _rate_limit_key(scope: str, identifier: str) -> str:
    safe_identifier = (identifier or "unknown").strip()[:120]
    return f"{scope}:{safe_identifier}"


def _get_rate_limit_entry(scope: str, identifier: str) -> Optional[dict]:
    key = _rate_limit_key(scope, identifier)
    try:
        return dal.get_rate_limit_state(key)
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Falha ao consultar rate-limit no banco; usando fallback local.")
        return _local_rate_failures.get(key)


def _clear_rate_limit(scope: str, identifier: str) -> None:
    key = _rate_limit_key(scope, identifier)
    _local_rate_failures.pop(key, None)
    try:
        dal.clear_rate_limit_state(key)
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Falha ao limpar rate-limit no banco.")


def _is_rate_limited(scope: str, identifier: str, max_attempts: int) -> tuple[bool, int]:
    """Retorna (bloqueado, segundos_restantes)."""
    entry = _get_rate_limit_entry(scope, identifier)
    if not entry:
        return False, 0
    count = int(entry.get("count") or entry.get("fail_count") or 0)
    blocked_until = float(entry.get("blocked_until") or 0)
    if count >= max_attempts:
        remaining = blocked_until - time.time()
        if remaining > 0:
            return True, int(remaining) + 1
        _clear_rate_limit(scope, identifier)
    return False, 0


def _register_rate_limit_failure(
    scope: str,
    identifier: str,
    max_attempts: int,
    block_seconds: int,
) -> None:
    key = _rate_limit_key(scope, identifier)
    try:
        dal.record_rate_limit_failure(key, max_attempts, block_seconds)
        return
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Falha ao registrar rate-limit no banco; usando fallback local.")

    entry = _local_rate_failures.setdefault(key, {"count": 0, "blocked_until": 0.0})
    now = time.time()
    if float(entry.get("blocked_until") or 0) <= now and int(entry.get("count") or 0) >= max_attempts:
        entry["count"] = 0
    entry["count"] += 1
    if entry["count"] >= max_attempts:
        entry["blocked_until"] = now + block_seconds


def _is_login_blocked(ip: str) -> tuple[bool, int]:
    return _is_rate_limited("login", ip, _LOGIN_MAX_ATTEMPTS)


def _register_login_failure(ip: str) -> None:
    _register_rate_limit_failure("login", ip, _LOGIN_MAX_ATTEMPTS, _LOGIN_BLOCK_SECONDS)


def _is_signup_blocked(ip: str) -> tuple[bool, int]:
    return _is_rate_limited("signup", ip, _SIGNUP_MAX_ATTEMPTS)


def _register_signup_failure(ip: str) -> None:
    _register_rate_limit_failure("signup", ip, _SIGNUP_MAX_ATTEMPTS, _SIGNUP_BLOCK_SECONDS)


_PUBLIC_PATHS = {"/favicon.ico", "/login", "/logout", "/solicitar-cadastro"}


@app.before_request
def require_login():
    if request.path.startswith("/static") or request.path in _PUBLIC_PATHS:
        return
    if not session.get("logged_in"):
        return redirect("/login")


def _constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(
        str(left or "").encode("utf-8"),
        str(right or "").encode("utf-8"),
    )


def _authenticate(username: str, password: str) -> Optional[dict]:
    """Valida credenciais. Retorna dict com dados de sessão ou None.

    Ordem de verificação:
      1. Usuário cadastrado em funcionarios (com senha_hash e ativo).
      2. Fallback do .env (APP_USERNAME/APP_PASSWORD) como super-admin.
    """
    if not username or not password:
        return None

    try:
        employee = dal.get_employee_by_username(username)
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Erro ao consultar funcionario durante autenticacao.")
        return None

    if employee and employee.get("senha_hash"):
        ativo_raw = str(employee.get("ativo", "")).strip().lower()
        is_active = ativo_raw not in {"false", "0", "nao", "não"}
        if is_active and check_password_hash(employee["senha_hash"], password):
            return {
                "logged_in": True,
                "user_id": employee.get("id_funcionario"),
                "user_name": employee.get("nome") or employee.get("usuario"),
                "role": _normalize_role(employee.get("perfil")),
            }

    fallback_user_ok = _constant_time_equal(username, APP_USERNAME) if _FALLBACK_ADMIN_ENABLED else False
    fallback_pass_ok = _constant_time_equal(password, APP_PASSWORD) if _FALLBACK_ADMIN_ENABLED else False
    if _FALLBACK_ADMIN_ENABLED and fallback_user_ok and fallback_pass_ok:
        return {
            "logged_in": True,
            "user_id": None,
            "user_name": APP_USERNAME,
            "role": ROLE_ADMIN,
        }

    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = _get_client_ip()
    blocked, remaining = _is_login_blocked(ip)
    if blocked:
        error = "Muitas tentativas. Tente novamente em alguns minutos."
        return render_template("login.html", error=error)

    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        auth = _authenticate(username, password)
        if auth:
            _clear_rate_limit("login", ip)
            session.clear()
            session.update(auth)
            landing_endpoint = "dashboard" if auth["role"] == ROLE_ADMIN else "meus_servicos"
            return redirect(url_for(landing_endpoint))
        _register_login_failure(ip)
        blocked, remaining = _is_login_blocked(ip)
        if blocked:
            error = "Muitas tentativas. Tente novamente em alguns minutos."
        else:
            error = "Usuário ou senha incorretos."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = redirect("/login")
    resp.delete_cookie("session")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


@app.route("/solicitar-cadastro", methods=["GET", "POST"])
def solicitar_cadastro():
    """Tela pública para que um funcionário solicite acesso ao sistema.

    A solicitação fica pendente até que um admin aprove ou reprove.
    """
    form_data = {"nome": "", "telefone": "", "cargo": "", "usuario": ""}
    ip = _get_client_ip()
    blocked, _remaining = _is_signup_blocked(ip)
    if blocked:
        return render_template(
            "solicitar_cadastro.html",
            form_data=form_data,
            error="Muitas solicitações em pouco tempo. Tente novamente em alguns minutos.",
        )
    if request.method == "POST":
        _register_signup_failure(ip)
        nome = (request.form.get("nome") or "").strip()
        telefone = (request.form.get("telefone") or "").strip()
        cargo = (request.form.get("cargo") or "").strip()
        usuario = (request.form.get("usuario") or "").strip()
        senha = request.form.get("senha") or ""
        confirmacao = request.form.get("senha_confirmacao") or ""
        form_data = {"nome": nome, "telefone": telefone, "cargo": cargo, "usuario": usuario}

        if not nome or not usuario or not senha:
            return render_template(
                "solicitar_cadastro.html",
                form_data=form_data,
                error="Preencha nome, usuário e senha.",
            )
        if not EMPLOYEE_USERNAME_RE.match(usuario):
            return render_template(
                "solicitar_cadastro.html",
                form_data=form_data,
                error="Usuário deve ter 3 a 40 caracteres (letras, números, ponto, hífen ou underline).",
            )
        password_error = _validate_password_strength(senha)
        if password_error:
            return render_template(
                "solicitar_cadastro.html",
                form_data=form_data,
                error=password_error,
            )
        if senha != confirmacao:
            return render_template(
                "solicitar_cadastro.html",
                form_data=form_data,
                error="As senhas não coincidem.",
            )

        try:
            existing_employee = dal.get_employee_by_username(usuario)
            existing_pending = dal.has_pending_signup_for_username(usuario)
        except Exception:  # pylint: disable=broad-except
            app.logger.exception("Erro ao verificar usuario existente em solicitacao de cadastro.")
            return render_template(
                "solicitar_cadastro.html",
                form_data=form_data,
                error="Não foi possível validar o usuário agora. Tente novamente em alguns minutos.",
            )
        if existing_employee or existing_pending:
            return render_template(
                "solicitar_cadastro.html",
                form_data=form_data,
                error="Este usuário já está em uso ou aguardando aprovação. Escolha outro.",
            )

        payload = {
            "nome": nome,
            "telefone": telefone,
            "cargo": cargo,
            "usuario": usuario,
            "senha_hash": generate_password_hash(senha),
        }
        dal.add_signup_request(payload)
        return render_template("solicitar_cadastro.html", form_data={}, success=True)

    return render_template("solicitar_cadastro.html", form_data=form_data)


@app.route("/solicitacoes")
@require_admin
def listar_solicitacoes():
    """Lista todas as solicitações de cadastro para o admin gerenciar."""
    pendentes = dal.get_signup_requests(status="pendente")
    historico = [
        s for s in dal.get_signup_requests()
        if s.get("status") != "pendente"
    ]
    return render_template(
        "solicitacoes.html",
        pendentes=pendentes,
        historico=historico,
    )


def _current_admin_label() -> str:
    """Identifica quem decidiu uma solicitação, pra registro de auditoria."""
    name = session.get("user_name") or "admin"
    user_id = session.get("user_id")
    return f"{name} (#{user_id})" if user_id else name


@app.route("/solicitacoes/<int:request_id>/aprovar", methods=["POST"])
@require_admin
def aprovar_solicitacao(request_id: int):
    solicitacao = dal.get_signup_request_by_id(request_id)
    if not solicitacao or solicitacao.get("status") != "pendente":
        flash("Solicitação não encontrada ou já decidida.", "warning")
        return redirect(url_for("listar_solicitacoes"))

    usuario = (solicitacao.get("usuario") or "").strip()
    if dal.get_employee_by_username(usuario):
        flash(
            f"Não foi possível aprovar: o usuário '{usuario}' já existe como funcionário ativo.",
            "danger",
        )
        return redirect(url_for("listar_solicitacoes"))

    employee_payload = {
        "nome": solicitacao.get("nome") or usuario,
        "telefone": solicitacao.get("telefone") or "",
        "cargo": solicitacao.get("cargo") or "",
        "observacoes": "",
        "ativo": True,
        "usuario": usuario,
        "senha_hash": solicitacao.get("senha_hash"),
        "perfil": ROLE_MECANICO,
    }
    dal.add_employee(employee_payload)
    dal.mark_signup_request_decision(request_id, "aprovada", _current_admin_label())
    flash(
        f"Cadastro de '{solicitacao.get('nome') or usuario}' aprovado. Perfil: Mecânico.",
        "success",
    )
    return redirect(url_for("listar_solicitacoes"))


@app.route("/solicitacoes/<int:request_id>/reprovar", methods=["POST"])
@require_admin
def reprovar_solicitacao(request_id: int):
    solicitacao = dal.get_signup_request_by_id(request_id)
    if not solicitacao or solicitacao.get("status") != "pendente":
        flash("Solicitação não encontrada ou já decidida.", "warning")
        return redirect(url_for("listar_solicitacoes"))

    motivo = (request.form.get("motivo") or "").strip() or None
    dal.mark_signup_request_decision(request_id, "reprovada", _current_admin_label(), motivo)
    flash("Solicitação reprovada.", "info")
    return redirect(url_for("listar_solicitacoes"))


# Informações fixas usadas no PDF do orçamento.
COMPANY_INFO = {
    "razao_social": "LB AUTOCAR",
    "cnpj": "56.994.095/0001-60",
    "endereco": "Rua Prof. Abílio Alencar, 104 - Alvorada 1, Manaus/AM",
    "telefone": "(92) 98839-8418",
    "email": "",
}


@app.template_filter("brl")
def format_brl(value) -> str:
    """Formata número como moeda pt-BR: 1234.56 → R$ 1.234,56"""
    try:
        v = float(value or 0)
    except (TypeError, ValueError):
        v = 0.0
    formatted = f"{v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"R$ {formatted}"


@app.context_processor
def inject_company_info():
    """Disponibiliza dados da empresa para todos os templates."""
    return {"company_info": COMPANY_INFO}


@app.context_processor
def inject_pending_signup_count():
    """Disponibiliza a contagem de solicitações pendentes para o admin."""
    if session.get("role") != ROLE_ADMIN:
        return {"pending_signup_count": 0}
    try:
        return {"pending_signup_count": dal.count_pending_signup_requests()}
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Erro ao contar solicitacoes pendentes.")
        return {"pending_signup_count": 0}
LOGO_SOURCE_PATH = os.path.join(PROJECT_DIR, "static", "logo.png")
TAXA_CARTAO_CREDITO = 0.03
VALIDADE_PADRAO = "5 dias corridos"
OBSERVACOES_PADRAO = (
    "Valores sujeitos a alteração após o período de validade. "
    "Prazo estimado de execução conforme disponibilidade na agenda."
)
PAYMENT_OPTIONS = [
    "PIX",
    "Dinheiro",
    "Cartão Débito",
    "Cartão Crédito",
    "Crediário Parceiro Bemol",
]
COMMERCIAL_TERMS_TEXT = (
    "Forma de pagamento: Transferência bancária, boleto ou cartão de crédito."
)
BUDGET_STATUS_PENDING_ADMIN = "Pendente validação admin"
BUDGET_STATUS_ADMIN_APPROVED = "Aprovado pelo admin"
FINALIZED_BUDGET_STATUSES = {"concluido", "finalizado"}
ADMIN_APPROVED_BUDGET_STATUSES = {
    "aprovado pelo admin",
    "aprovado",
    *FINALIZED_BUDGET_STATUSES,
}
FINANCIAL_ENTRY_CATEGORY_BUDGET = "Serviço Oficina"
FINANCE_EXPENSE_TYPES = {
    "Despesas Fixas": [
        "Infraestrutura - Aluguel do ponto comercial",
        "Infraestrutura - IPTU",
        "Infraestrutura - Condomínio",
        "Infraestrutura - Seguro do espaço/equipamentos",
        "Energia e utilidades - Energia elétrica",
        "Energia e utilidades - Água",
        "Energia e utilidades - Internet e telefone",
        "Sistemas e softwares de gestão",
        "Assinatura de contabilidade",
        "Pessoal - Salários",
        "Pessoal - Encargos (INSS/FGTS etc.)",
        "Pessoal - Vale-transporte",
        "Pessoal - Vale-alimentação",
        "Administrativas - Contabilidade",
        "Administrativas - Taxas bancárias",
        "Administrativas - Taxas de cartão",
        "Administrativas - Licenças e alvarás",
        "Manutenção preventiva",
    ],
    "Despesas Variáveis": [
        "Materiais e peças - Componentes automotivos",
        "Materiais e peças - Lubrificantes",
        "Materiais e peças - Embalagens/limpeza do serviço",
        "Operação - Mão de obra variável",
        "Operação - Produtos químicos",
        "Operação - Gases industriais",
        "Despesas comerciais - Comissões",
        "Despesas comerciais - Marketing/divulgação",
    ],
    "Investimentos (CAPEX)": [
        "Equipamentos - Elevador/compressor",
        "Equipamentos - Scanner/diagnóstico",
        "Equipamentos - Ferramentas especiais",
        "Infraestrutura - Reforma/galpão",
        "Infraestrutura - Sistema elétrico/exaustão",
    ],
    "Despesas Financeiras": [
        "Juros de parcelamentos",
        "Taxa de antecipação",
        "Multas",
        "Empréstimos/financiamentos",
    ],
    "Despesas de apoio e limpeza": [
        "Produtos de limpeza",
        "Uniformes e EPIs",
        "Lavagem de panos industriais",
        "Coleta de resíduos automotivos",
    ],
}
MONTH_NAMES = [
    "Janeiro",
    "Fevereiro",
    "Março",
    "Abril",
    "Maio",
    "Junho",
    "Julho",
    "Agosto",
    "Setembro",
    "Outubro",
    "Novembro",
    "Dezembro",
]

# Garante criação das planilhas quando o servidor inicia.
dal.ensure_all_files_exist()


@app.route("/favicon.ico")
def favicon():
    """Serve a logo do aplicativo para uso na interface e na aba do navegador."""
    logo_path = os.path.join(PROJECT_DIR, "static", "logo.png")
    if not os.path.exists(logo_path):
        return ("", 404)
    return send_file(logo_path, mimetype="image/png")


@app.route("/atualizar-base", methods=["POST"])
@require_admin
def atualizar_base():
    """Botão global que força a leitura/validação das planilhas de dados."""
    dal.ensure_all_files_exist()
    data_files = dal.get_data_files()
    saved_at = "; ".join(f"{nome}: {caminho}" for nome, caminho in data_files.items())
    app.logger.info("Atualização solicitada. Arquivos de dados em uso: %s", saved_at)
    flash("Base de dados atualizada a partir dos arquivos locais.", "success")
    return _safe_redirect_from_referrer("dashboard")


def _parse_date(date_str: str) -> datetime:
    """Converte strings de data no formato YYYY-MM-DD. Retorna hoje em caso de formato inválido."""
    if not date_str:
        return datetime.today()
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return datetime.today()


def _parse_brl_number(raw_value: str) -> float:
    """Converte valor monetário em formato pt-BR/en para float (ex.: 1.234,56 ou 1234.56)."""
    value = (raw_value or "").strip()
    if not value:
        return 0.0

    if "," in value and "." in value:
        # Assume formato pt-BR com separador de milhar.
        value = value.replace(".", "").replace(",", ".")
    elif "," in value:
        # Formato com vírgula decimal.
        value = value.replace(",", ".")

    return float(value)


def _generate_service_order_number(now: Optional[datetime] = None) -> str:
    """Gera OS no formato ORDEMddmmaaaaHHMM."""
    return "ORDEM" + (now or datetime.today()).strftime("%d%m%Y%H%M")


def _service_order_label(service: dict) -> str:
    ordem = str((service or {}).get("ordem_servico") or "").strip()
    return ordem or f"#{(service or {}).get('id_servico')}"


def _get_service_group(service: dict) -> list:
    ordem = str((service or {}).get("ordem_servico") or "").strip()
    if not ordem:
        return [service] if service else []
    services = dal.get_services_by_order(ordem)
    return services or ([service] if service else [])


def _get_budget_service_records(budget_id: int, services_df: Optional[pd.DataFrame] = None) -> list:
    if services_df is None:
        services_df = dal.get_all_services()
    if services_df.empty or "id_orcamento" not in services_df.columns:
        return []
    related_budget = pd.to_numeric(services_df["id_orcamento"], errors="coerce")
    budget_services = services_df[related_budget == budget_id].copy()
    if budget_services.empty:
        return []
    if "id_servico" in budget_services.columns:
        budget_services = budget_services.sort_values("id_servico")
    return budget_services.to_dict(orient="records")


def _service_order_from_records(services: list) -> str:
    for service in services:
        ordem = str((service or {}).get("ordem_servico") or "").strip()
        if ordem:
            return ordem
    return ""


def _sync_budget_services_from_items(
    budget_id: int,
    budget: dict,
    items: list,
    *,
    data_execucao: datetime,
    status: str,
    responsavel: str,
) -> dict:
    existing_services = _get_budget_service_records(budget_id)
    ordem_servico = _service_order_from_records(existing_services) or _generate_service_order_number()
    data_execucao_str = data_execucao.strftime("%Y-%m-%d")
    created_count = 0
    updated_count = 0

    for index, item in enumerate(items):
        payload = {
            "id_orcamento": budget_id,
            "id_cliente": budget.get("id_cliente"),
            "data_execucao": data_execucao_str,
            "descricao_servico": item.get("descricao"),
            "tipo_servico": item.get("tipo"),
            "valor": item.get("subtotal"),
            "observacoes": f"Gerado pelo orçamento #{budget_id}",
            "responsavel": responsavel,
            "status": status,
            "ordem_servico": ordem_servico,
        }
        if index < len(existing_services):
            service_id = _coerce_int(existing_services[index].get("id_servico"))
            if service_id:
                dal.update_service(service_id, payload)
                updated_count += 1
                continue
        dal.add_service(payload)
        created_count += 1

    for service in existing_services[len(items):]:
        service_id = _coerce_int(service.get("id_servico"))
        if service_id:
            dal.update_service(
                service_id,
                {
                    "data_execucao": data_execucao_str,
                    "responsavel": responsavel,
                    "status": status,
                    "ordem_servico": ordem_servico,
                },
            )
            updated_count += 1

    return {
        "ordem_servico": ordem_servico,
        "created_count": created_count,
        "updated_count": updated_count,
    }


def _build_service_items_from_services(services: list) -> list:
    items = []
    for service in services:
        valor = float(service.get("valor") or 0)
        items.append({
            "descricao": service.get("descricao_servico") or "Serviço",
            "quantidade": 1,
            "valor_unitario": valor,
            "subtotal": valor,
        })
    return items


def _normalize_status(value: str) -> str:
    """Remove acentos e padroniza para facilitar comparações de status."""
    if not value:
        return ""
    normalized = unicodedata.normalize("NFKD", value)
    normalized = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    return normalized.strip().lower()


def _budget_status_display(status: str) -> str:
    """Retorna um texto amigável para exibição do status do orçamento."""
    raw_status = str(status or "").strip()
    if not raw_status:
        return "Sem status"

    status_map = {
        "pendente validacao admin": BUDGET_STATUS_PENDING_ADMIN,
        "pendente validação admin": BUDGET_STATUS_PENDING_ADMIN,
        "aprovado pelo admin": BUDGET_STATUS_ADMIN_APPROVED,
        "aprovado": "Aprovado",
        "concluido": "Concluído",
        "finalizado": "Finalizado",
        "reprovado": "Reprovado",
        "pendente": "Pendente",
    }

    normalized_status = _normalize_status(raw_status)
    return status_map.get(normalized_status, raw_status.replace("_", " ").capitalize())


def _is_budget_finalized(status: str) -> bool:
    """Indica se um orçamento está em estado que impede nova efetivação."""
    return _normalize_status(status) in FINALIZED_BUDGET_STATUSES


def _is_budget_admin_approved(status: str) -> bool:
    """Indica se o orçamento já passou pela validação administrativa."""
    return _normalize_status(status) in ADMIN_APPROVED_BUDGET_STATUSES


def _is_budget_pending_admin(status: str) -> bool:
    """Indica se o orçamento ainda precisa da validação administrativa."""
    status_norm = _normalize_status(status)
    return status_norm not in ADMIN_APPROVED_BUDGET_STATUSES and status_norm != "reprovado"


def _format_quantity_display(value) -> str:
    """Formata quantidades para o PDF, mantendo texto caso não seja numérico."""
    if value is None or value == "":
        return "-"
    try:
        numeric = float(value)
        if numeric.is_integer():
            return str(int(numeric))
        return f"{numeric:.2f}".rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        return str(value)


def _build_client_address(client: dict) -> str:
    """Monta uma string de endereço amigável para o PDF."""
    parts: List[str] = []

    def _as_text(value):
        if value is None:
            return ""
        if isinstance(value, float) and math.isnan(value):
            return ""
        text = str(value).strip()
        if text.lower() in {"nan", "none"}:
            return ""
        return text

    street = " ".join(
        text for text in [_as_text(client.get("endereco_rua")), _as_text(client.get("endereco_numero"))] if text
    )
    if street:
        parts.append(street)

    bairro = _as_text(client.get("endereco_bairro"))
    if bairro:
        parts.append(bairro)

    city_state = ", ".join(
        text for text in [_as_text(client.get("endereco_cidade")), _as_text(client.get("endereco_uf"))] if text
    )
    if city_state:
        parts.append(city_state)

    cep = _as_text(client.get("endereco_cep"))
    if cep:
        parts.append(f"CEP {cep}")

    return " - ".join(parts) if parts else "Não informado"


def _pdf_safe_text(value) -> str:
    """Remove caracteres fora do latin-1 para evitar erros na geração do PDF."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.encode("latin-1", "ignore").decode("latin-1")


def _get_pdf_logo_path() -> Optional[str]:
    """Retorna o caminho de uma imagem compatível com o PDF a partir do ícone."""
    if not os.path.exists(LOGO_SOURCE_PATH):
        return None

    ext = os.path.splitext(LOGO_SOURCE_PATH)[1].lower()
    if ext in {".png", ".jpg", ".jpeg"}:
        return LOGO_SOURCE_PATH

    if Image is None:
        return None

    try:
        if not os.path.exists(LOGO_SOURCE_PATH):
            return None
        return LOGO_SOURCE_PATH
    except Exception:
        return None


def _slugify_filename(value: str) -> str:
    """Gera um identificador simples para uso em nomes de arquivos."""
    if not value:
        return "recibo"
    normalized = unicodedata.normalize("NFKD", value)
    ascii_text = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    safe = "".join(ch if ch.isalnum() else "_" for ch in ascii_text).strip("_")
    return safe.lower() or "recibo"


def _normalize_whatsapp_number(value: str) -> Optional[str]:
    """Retorna um número de WhatsApp pronto para wa.me, com DDI se possível."""
    if not value:
        return None
    digits = re.sub(r"\D+", "", str(value))
    if not digits:
        return None
    digits = digits.lstrip("0")
    if digits.startswith("55") and len(digits) >= 11:
        return digits
    if len(digits) in {10, 11}:
        return f"55{digits}"
    return digits if len(digits) >= 11 else None


def _build_whatsapp_url(phone: str, text: str) -> str:
    """Constrói um link do WhatsApp para o cliente ou retorna o link genérico se não houver telefone."""
    encoded_text = quote(text or "")
    normalized_phone = _normalize_whatsapp_number(phone)
    if normalized_phone:
        return f"https://wa.me/{normalized_phone}?text={encoded_text}"
    return f"https://wa.me/?text={encoded_text}"


def _format_date(date_value) -> str:
    """Padroniza exibição de datas mesmo quando vierem como Timestamp."""
    if date_value is None or pd.isna(date_value):
        return "-"
    try:
        return pd.to_datetime(date_value).strftime("%d/%m/%Y")
    except Exception:  # pylint: disable=broad-except
        return str(date_value)


def _format_cpf_cnpj(value: str) -> str:
    """Aplica máscara de CPF ou CNPJ conforme a quantidade de dígitos."""
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if not digits:
        return ""

    if len(digits) > 11:
        digits = digits[:14]
        if len(digits) <= 2:
            return digits
        if len(digits) <= 5:
            return f"{digits[:2]}.{digits[2:]}"
        if len(digits) <= 8:
            return f"{digits[:2]}.{digits[2:5]}.{digits[5:]}"
        if len(digits) <= 12:
            return f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:]}"
        return f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:]}"

    digits = digits[:11]
    if len(digits) <= 3:
        return digits
    if len(digits) <= 6:
        return f"{digits[:3]}.{digits[3:]}"
    if len(digits) <= 9:
        return f"{digits[:3]}.{digits[3:6]}.{digits[6:]}"
    return f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}"


def _coerce_int(value) -> Optional[int]:
    """Converte valores vindos do banco/DataFrame para inteiro, preservando vazio."""
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except TypeError:
        pass
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return None
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return None


def _coerce_float(value) -> float:
    try:
        if value is None or pd.isna(value):
            return 0.0
    except TypeError:
        pass
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _repair_financial_text(value) -> str:
    """Corrige textos financeiros antigos que foram gravados com '?' no lugar de acentos."""
    if value is None:
        return ""
    text = str(value)
    replacements = {
        "Or?amento": "Orçamento",
        "or?amento": "orçamento",
        "Servi?o": "Serviço",
        "servi?o": "serviço",
        "Sa?da": "Saída",
        "sa?da": "saída",
        "Entrada": "Entrada",
        "Descri??o": "Descrição",
        "descri??o": "descrição",
        "Cr?dito": "Crédito",
        "cr?dito": "crédito",
        "D?bito": "Débito",
        "d?bito": "débito",
        "Cart?o": "Cartão",
        "cart?o": "cartão",
        "N?o": "Não",
        "n?o": "não",
        "Or�amento": "Orçamento",
        "Servi�o": "Serviço",
        "Sa�da": "Saída",
        "Descri��o": "Descrição",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def _budget_financial_description(budget_id: int, client_name: str) -> str:
    client_name = str(client_name or "").strip() or "Cliente não informado"
    return f"Orçamento #{budget_id} - {client_name}"


def _budget_financial_date(budget: dict) -> str:
    for field in ("data_conclusao", "data_aprovacao", "data_criacao"):
        value = budget.get(field)
        try:
            if pd.isna(value):
                continue
        except TypeError:
            pass
        text = str(value or "").strip()
        if text and text.lower() not in {"nan", "none", "null"}:
            return text
    return datetime.today().strftime("%Y-%m-%d")


def _find_budget_id_in_financial_entry(entry: dict) -> Optional[int]:
    related_budget_id = _coerce_int(entry.get("relacionado_orcamento_id"))
    if related_budget_id:
        return related_budget_id

    description = str(entry.get("descricao") or "")
    match = re.search(r"#\s*(\d+)", description)
    if match:
        return int(match.group(1))
    return None


def _build_financial_entries_by_budget(financial_df: pd.DataFrame) -> dict:
    entries_by_budget = {}
    if financial_df.empty:
        return entries_by_budget

    for entry in financial_df.to_dict(orient="records"):
        if _normalize_status(entry.get("tipo_lancamento")) != "entrada":
            continue
        budget_id = _find_budget_id_in_financial_entry(entry)
        if budget_id and budget_id not in entries_by_budget:
            entries_by_budget[budget_id] = entry
    return entries_by_budget


def _sync_completed_budget_financial_entries() -> int:
    """Garante entrada financeira para todo orçamento concluído, sem duplicar."""
    changes = 0
    budgets_df = dal.get_all_budgets()
    financial_df = dal.get_all_financial_entries()

    if financial_df.empty:
        financial_df = pd.DataFrame(columns=dal.FINANCEIRO_COLUMNS)

    # Corrige textos antigos de lançamentos manuais ou gerados antes do ajuste.
    for entry in financial_df.to_dict(orient="records"):
        entry_id = _coerce_int(entry.get("id_lancamento"))
        if not entry_id:
            continue
        updates = {}
        repaired_description = _repair_financial_text(entry.get("descricao"))
        repaired_category = _repair_financial_text(entry.get("categoria"))
        if repaired_description != (entry.get("descricao") or ""):
            updates["descricao"] = repaired_description
        if repaired_category != (entry.get("categoria") or ""):
            updates["categoria"] = repaired_category
        if updates:
            dal.update_financial_entry(entry_id, updates)
            changes += 1
            for key, value in updates.items():
                entry[key] = value

    if budgets_df.empty:
        return changes

    clients_df = dal.get_all_clients()
    client_names = {}
    if not clients_df.empty:
        for client in clients_df.to_dict(orient="records"):
            client_id = _coerce_int(client.get("id_cliente"))
            if client_id:
                client_names[client_id] = client.get("nome", "")

    entries_by_budget = _build_financial_entries_by_budget(financial_df)

    for budget in budgets_df.to_dict(orient="records"):
        if not _is_budget_finalized(budget.get("status")):
            continue

        budget_id = _coerce_int(budget.get("id_orcamento"))
        if not budget_id:
            continue

        client_name = client_names.get(_coerce_int(budget.get("id_cliente")), "")
        payload = {
            "data": _budget_financial_date(budget),
            "tipo_lancamento": "Entrada",
            "categoria": FINANCIAL_ENTRY_CATEGORY_BUDGET,
            "descricao": _budget_financial_description(budget_id, client_name),
            "valor": _coerce_float(budget.get("valor_total")),
            "relacionado_orcamento_id": budget_id,
            "relacionado_servico_id": None,
        }

        existing_entry = entries_by_budget.get(budget_id)
        if not existing_entry:
            new_id = dal.add_financial_entry(payload)
            payload["id_lancamento"] = new_id
            entries_by_budget[budget_id] = payload
            changes += 1
            continue

        entry_id = _coerce_int(existing_entry.get("id_lancamento"))
        if not entry_id:
            continue

        updates = {}
        for field in ("data", "tipo_lancamento", "categoria", "descricao"):
            if str(existing_entry.get(field) or "") != str(payload[field]):
                updates[field] = payload[field]
        if round(_coerce_float(existing_entry.get("valor")), 2) != round(payload["valor"], 2):
            updates["valor"] = payload["valor"]
        if _coerce_int(existing_entry.get("relacionado_orcamento_id")) != budget_id:
            updates["relacionado_orcamento_id"] = budget_id
        if _coerce_int(existing_entry.get("relacionado_servico_id")) is not None:
            updates["relacionado_servico_id"] = None

        if updates:
            dal.update_financial_entry(entry_id, updates)
            existing_entry.update(updates)
            changes += 1

    return changes


_last_sync_time: float = 0.0
_SYNC_COOLDOWN_SECONDS = 60


def _sync_completed_budget_financial_entries_safely() -> int:
    global _last_sync_time
    import time
    now = time.monotonic()
    if now - _last_sync_time < _SYNC_COOLDOWN_SECONDS:
        return 0
    try:
        result = _sync_completed_budget_financial_entries()
        _last_sync_time = time.monotonic()
        return result
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Falha ao sincronizar orçamentos concluídos com o financeiro.")
        return 0


def _get_active_employees() -> list:
    """Retorna lista de funcionários ativos como dicts, pronta para usar nos templates."""
    employees_df = dal.get_all_employees()
    if "ativo" not in employees_df.columns:
        employees_df["ativo"] = True
    active_mask = ~employees_df["ativo"].astype(str).str.lower().isin({"false", "0", "nao", "não"})
    return employees_df[active_mask].fillna("").to_dict(orient="records")


def _normalize_person_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", str(value or ""))
    normalized = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    return " ".join(normalized.casefold().split())


def _employee_status_label(employee: dict) -> str:
    inactive_values = {"false", "0", "nao", "não"}
    return "Inativo" if str(employee.get("ativo", "")).strip().lower() in inactive_values else "Ativo"


def _find_employee_duplicate(nome: str, ignore_employee_id: Optional[int] = None) -> Optional[dict]:
    target = _normalize_person_name(nome)
    if not target:
        return None

    employees_df = dal.get_all_employees().fillna("")
    for employee in employees_df.to_dict(orient="records"):
        employee_id = _coerce_int(employee.get("id_funcionario"))
        if ignore_employee_id and employee_id == ignore_employee_id:
            continue
        if _normalize_person_name(employee.get("nome")) == target:
            return employee
    return None


def _flash_employee_duplicate(employee: dict) -> None:
    flash(
        f'Já tem cadastro dessa pessoa como funcionário: "{employee.get("nome", "")}" '
        f'(Status: {_employee_status_label(employee)}). Use o botão "Editar" para atualizar os dados.',
        "warning",
    )


def _split_expense_category(category_value: str) -> Tuple[str, str]:
    """Separa o texto salvo no financeiro em tipo e categoria da despesa."""
    text = str(category_value or "").strip()
    for expense_type, categories in FINANCE_EXPENSE_TYPES.items():
        prefix = f"{expense_type} - "
        if text.startswith(prefix):
            category = text[len(prefix):]
            if category in categories:
                return expense_type, category
    return "", ""


def _build_expense_payload_from_form(form) -> Tuple[Optional[dict], Optional[str]]:
    data = form.get("data_saida", "").strip()
    tipo_despesa = form.get("tipo_despesa", "").strip()
    categoria = form.get("categoria", "").strip()
    descricao = form.get("descricao", "").strip()

    try:
        valor = _parse_brl_number(form.get("valor", "0"))
    except ValueError:
        return None, "Valor inválido. Use apenas números (ex.: 278,00)."

    try:
        data_saida = _parse_date(data)
    except ValueError:
        return None, "Data inválida para a despesa."
    if valor <= 0:
        return None, "Informe um valor maior que zero para a despesa."
    if tipo_despesa not in FINANCE_EXPENSE_TYPES:
        return None, "Selecione um tipo de despesa válido."
    if categoria not in FINANCE_EXPENSE_TYPES[tipo_despesa]:
        return None, "Selecione uma categoria correspondente ao tipo escolhido."
    if not descricao:
        return None, "Informe uma descrição para a despesa."

    orcamento_id_raw = form.get("relacionado_orcamento_id", "").strip()
    try:
        relacionado_orcamento_id = int(orcamento_id_raw) if orcamento_id_raw else None
    except ValueError:
        relacionado_orcamento_id = None

    return {
        "data": data_saida.strftime("%Y-%m-%d"),
        "tipo_lancamento": "Saída",
        "categoria": f"{tipo_despesa} - {categoria}",
        "descricao": descricao,
        "valor": valor,
        "relacionado_orcamento_id": relacionado_orcamento_id,
        "relacionado_servico_id": None,
    }, None


def _is_expense_entry(entry: dict) -> bool:
    value = str((entry or {}).get("tipo_lancamento") or "").strip().lower()
    return _normalize_status(value) == "saida" or value in {"sa?da", "sa�da"}



@app.route("/")
def landing():
    session.pop("has_entered", None)
    return render_template("landing.html")


@app.route("/entrar", methods=["POST"])
def enter_app():
    session["has_entered"] = True
    landing_endpoint = "dashboard" if session.get("role") == ROLE_ADMIN else "listar_orcamentos"
    return redirect(url_for(landing_endpoint))


@app.route("/dashboard")
@require_admin
def dashboard():
    _sync_completed_budget_financial_entries_safely()
    clients_df = dal.get_all_clients()
    budgets_df = dal.get_all_budgets()
    financial_df = dal.get_all_financial_entries()
    services_df = dal.get_all_services()

    total_clients = len(clients_df)
    if not budgets_df.empty and "status" in budgets_df.columns:
        status_norm = budgets_df["status"].fillna("").astype(str).apply(_normalize_status)
        open_mask = (~status_norm.isin(FINALIZED_BUDGET_STATUSES)) & (status_norm != "reprovado")
        total_open_budgets = int(open_mask.sum())
    else:
        total_open_budgets = 0

    financial_df["data"] = pd.to_datetime(financial_df["data"], errors="coerce")
    if "tipo_lancamento" not in financial_df.columns:
        financial_df["tipo_lancamento"] = ""
    financial_df["tipo_lancamento_norm"] = (
        financial_df["tipo_lancamento"].fillna("").astype(str).apply(_normalize_status)
    )
    financial_df["valor"] = pd.to_numeric(financial_df.get("valor"), errors="coerce").fillna(0)
    today = datetime.today()
    selected_month = today.month
    selected_year = today.year

    try:
        selected_month = int(request.args.get("mes", selected_month))
    except (TypeError, ValueError):
        selected_month = today.month
    if selected_month < 1 or selected_month > 12:
        selected_month = today.month

    try:
        selected_year = int(request.args.get("ano", selected_year))
    except (TypeError, ValueError):
        selected_year = today.year

    filtered_financial = financial_df[
        (financial_df["data"].dt.month == selected_month)
        & (financial_df["data"].dt.year == selected_year)
    ]
    entradas = filtered_financial[filtered_financial["tipo_lancamento_norm"] == "entrada"]["valor"].sum()
    saidas = filtered_financial[filtered_financial["tipo_lancamento_norm"] == "saida"]["valor"].sum()

    available_years = set(financial_df["data"].dropna().dt.year.tolist()) if not financial_df.empty else set()
    available_years.add(today.year)
    year_options = sorted(available_years)

    reference_date = datetime(selected_year, selected_month, 1)
    months_range = pd.date_range(reference_date - pd.DateOffset(months=11), periods=12, freq="MS")
    chart_labels: List[str] = []
    chart_entradas: List[float] = []
    chart_saidas: List[float] = []
    chart_saldo: List[float] = []
    for month_start in months_range:
        mask = (financial_df["data"].dt.month == month_start.month) & (
            financial_df["data"].dt.year == month_start.year
        )
        month_df = financial_df[mask]
        entradas_mes = month_df[month_df["tipo_lancamento_norm"] == "entrada"]["valor"].sum()
        saidas_mes = month_df[month_df["tipo_lancamento_norm"] == "saida"]["valor"].sum()
        chart_labels.append(month_start.strftime("%b/%Y"))
        chart_entradas.append(round(float(entradas_mes or 0), 2))
        chart_saidas.append(round(float(saidas_mes or 0), 2))
        chart_saldo.append(round(chart_entradas[-1] - chart_saidas[-1], 2))

    selected_month_name = MONTH_NAMES[selected_month - 1]

    # Resumo por responsável de execução
    if "responsavel" not in services_df.columns:
        services_df["responsavel"] = ""
    services_df["valor"] = pd.to_numeric(services_df.get("valor"), errors="coerce").fillna(0)
    resumo_execucao = (
        services_df.groupby("responsavel")
        .agg(qtd_servicos=("id_servico", "count"), total_receita=("valor", "sum"))
        .reset_index()
    )
    resumo_execucao = resumo_execucao.sort_values("total_receita", ascending=False)
    executores = resumo_execucao.to_dict(orient="records")

    # Orçamentos pendentes de aprovação administrativa
    pending_budgets = []
    if not budgets_df.empty:
        clients_lookup = {}
        if not clients_df.empty:
            clients_lookup = {
                _coerce_int(client.get("id_cliente")): client.get("nome", "")
                for client in clients_df.fillna("").to_dict(orient="records")
            }
        for _, row in budgets_df.iterrows():
            status_norm = _normalize_status(row.get("status", ""))
            if status_norm not in ADMIN_APPROVED_BUDGET_STATUSES and status_norm != "reprovado":
                budget_dict = row.to_dict()
                budget_dict["status_display"] = _budget_status_display(budget_dict.get("status", ""))
                budget_dict["cliente_nome"] = clients_lookup.get(_coerce_int(row.get("id_cliente")), "Cliente removido")
                budget_dict["valor_display"] = format_brl(_coerce_float(row.get("valor_total", 0)))
                pending_budgets.append(budget_dict)

    # Serviços pendentes de aprovação (status = Pendente)
    pending_services = []
    if not services_df.empty:
        clients_lookup = {}
        if not clients_df.empty:
            clients_lookup = {
                _coerce_int(client.get("id_cliente")): client.get("nome", "")
                for client in clients_df.fillna("").to_dict(orient="records")
            }
        for _, row in services_df.iterrows():
            status_norm = (str(row.get("status", "")).lower()).strip()
            if status_norm == "pendente":
                service_dict = row.to_dict()
                service_dict["cliente_nome"] = clients_lookup.get(_coerce_int(row.get("id_cliente")), "Cliente removido")
                service_dict["valor_display"] = format_brl(_coerce_float(row.get("valor", 0)))
                pending_services.append(service_dict)

    latest_budget = None
    if not budgets_df.empty:
        clients_lookup = {}
        if not clients_df.empty:
            clients_lookup = {
                _coerce_int(client.get("id_cliente")): client.get("nome", "")
                for client in clients_df.fillna("").to_dict(orient="records")
            }
        latest_candidates = budgets_df.copy()
        latest_candidates["id_orcamento_num"] = pd.to_numeric(
            latest_candidates.get("id_orcamento"), errors="coerce"
        ).fillna(0)
        latest_candidates["data_sort"] = pd.to_datetime(
            latest_candidates.get("data_criacao"), errors="coerce"
        )
        latest_row = latest_candidates.sort_values(
            ["data_sort", "id_orcamento_num"], ascending=[False, False]
        ).iloc[0].to_dict()
        latest_status = latest_row.get("status") or ""
        latest_budget = {
            "id_orcamento": _coerce_int(latest_row.get("id_orcamento")),
            "cliente": clients_lookup.get(_coerce_int(latest_row.get("id_cliente")), "Cliente removido"),
            "data": _format_date(latest_row.get("data_criacao")),
            "status": latest_status,
            "valor": _coerce_float(latest_row.get("valor_total")),
            "is_finalizado": _is_budget_finalized(latest_status),
            "is_reprovado": _normalize_status(latest_status) == "reprovado",
        }

    return render_template(
        "index.html",
        total_clients=total_clients,
        total_open_budgets=total_open_budgets,
        total_entradas=entradas,
        total_saidas=saidas,
        saldo=entradas - saidas,
        selected_month=selected_month,
        selected_year=selected_year,
        month_options=list(enumerate(MONTH_NAMES, start=1)),
        year_options=year_options,
        selected_month_name=selected_month_name,
        chart_labels=chart_labels,
        chart_entradas=chart_entradas,
        chart_saidas=chart_saidas,
        chart_saldo=chart_saldo,
        executores=executores,
        latest_budget=latest_budget,
        pending_budgets=pending_budgets,
        pending_services=pending_services,
    )


CLIENT_FIELDS = [
    "nome",
    "cpf_cnpj",
    "telefone_whatsapp",
    "email",
    "endereco_rua",
    "endereco_numero",
    "endereco_bairro",
    "endereco_cidade",
    "endereco_uf",
    "endereco_cep",
    "observacoes",
]
EMPLOYEE_FIELDS = ["nome", "telefone", "cargo", "observacoes"]
EMPLOYEE_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")
PASSWORD_MIN_LENGTH = 8
PASSWORD_HAS_LETTER_RE = re.compile(r"[A-Za-z]")
PASSWORD_HAS_NUMBER_RE = re.compile(r"\d")


def _validate_password_strength(password: str) -> Optional[str]:
    if len(password or "") < PASSWORD_MIN_LENGTH:
        return f"A senha precisa ter pelo menos {PASSWORD_MIN_LENGTH} caracteres."
    if not PASSWORD_HAS_LETTER_RE.search(password) or not PASSWORD_HAS_NUMBER_RE.search(password):
        return "A senha precisa conter pelo menos uma letra e um número."
    return None


def _build_employee_access_payload(form, *, existing: Optional[dict] = None) -> Tuple[dict, Optional[str]]:
    """Lê usuario/senha/perfil do form e devolve campos a atualizar + erro.

    Se existing for None (novo funcionário): senha vira obrigatória caso usuario seja informado.
    Se existing for dict (edição): senha vazia mantém a atual.
    """
    usuario_raw = (form.get("usuario") or "").strip()
    senha = form.get("senha") or ""
    perfil = _normalize_role(form.get("perfil") or "")

    has_existing_user = bool(existing and (existing.get("usuario") or "").strip())
    has_existing_pwd = bool(existing and existing.get("senha_hash"))

    if not usuario_raw and not has_existing_user:
        # Funcionário sem acesso ao sistema (apenas registro de pessoal).
        return {"usuario": None, "senha_hash": None, "perfil": None}, None

    if usuario_raw and not EMPLOYEE_USERNAME_RE.match(usuario_raw):
        return {}, "Usuário deve ter 3 a 40 caracteres (letras, números, ponto, hífen ou underline)."

    duplicate = dal.get_employee_by_username(usuario_raw) if usuario_raw else None
    if duplicate and (not existing or duplicate.get("id_funcionario") != existing.get("id_funcionario")):
        return {}, f"O usuário '{usuario_raw}' já está em uso por outro funcionário."

    payload: dict = {"perfil": perfil}
    payload["usuario"] = usuario_raw or (existing.get("usuario") if existing else None)

    if senha:
        password_error = _validate_password_strength(senha)
        if password_error:
            return {}, password_error
        payload["senha_hash"] = generate_password_hash(senha)
    elif not has_existing_pwd:
        return {}, f"Defina uma senha de pelo menos {PASSWORD_MIN_LENGTH} caracteres para conceder acesso."

    return payload, None


def _build_vehicles_map() -> dict:
    """Retorna dict {id_cliente: [veiculos]} para uso nas views."""
    all_vehicles = dal.get_all_vehicles()
    vmap: dict = {}
    for v in all_vehicles:
        cid = v["id_cliente"]
        vmap.setdefault(cid, []).append(v)
    return vmap


def _get_veiculo_for_orcamento(budget: dict, client: dict) -> dict:
    """Retorna veículo do orçamento (tabela veiculos) ou fallback nos campos legados do cliente."""
    id_veiculo = budget.get("id_veiculo")
    if id_veiculo:
        try:
            v = dal.get_vehicle_by_id(int(id_veiculo))
            if v:
                return v
        except (TypeError, ValueError):
            pass
    return {
        "id_veiculo": None,
        "marca": (client or {}).get("carro_marca", ""),
        "modelo": (client or {}).get("carro_modelo", ""),
        "ano": (client or {}).get("carro_ano", ""),
        "placa": (client or {}).get("carro_placa", ""),
        "observacoes": "",
    }


@app.route("/clientes", methods=["GET", "POST"])
def clientes():
    if request.method == "POST":
        payload = {field: request.form.get(field, "").strip() for field in CLIENT_FIELDS}
        payload["cpf_cnpj"] = _format_cpf_cnpj(payload.get("cpf_cnpj"))
        if not payload.get("nome"):
            flash("Informe o nome do cliente para realizar o cadastro.", "danger")
            return redirect(url_for("clientes"))
        # Mantém campos legados vazios para compatibilidade
        payload.update({"carro_marca": "", "carro_modelo": "", "carro_ano": "", "carro_placa": ""})
        client_id = dal.add_client(payload)

        marcas  = request.form.getlist("carro_marca[]")
        modelos = request.form.getlist("carro_modelo[]")
        anos    = request.form.getlist("carro_ano[]")
        placas  = request.form.getlist("carro_placa[]")
        cores   = request.form.getlist("carro_cor[]")
        for i in range(len(marcas)):
            marca  = marcas[i].strip()
            modelo = modelos[i].strip() if i < len(modelos) else ""
            ano    = anos[i].strip()    if i < len(anos)    else ""
            placa  = placas[i].strip()  if i < len(placas)  else ""
            cor    = cores[i].strip()   if i < len(cores)   else ""
            if marca or modelo or placa:
                dal.add_vehicle({"id_cliente": client_id, "marca": marca,
                                 "modelo": modelo, "ano": ano, "placa": placa,
                                 "cor": cor, "observacoes": ""})

        flash("Cliente cadastrado com sucesso!", "success")
        return redirect(url_for("clientes"))

    clients_df = dal.get_all_clients().fillna("")
    clients = clients_df.to_dict(orient="records")
    vmap = _build_vehicles_map()
    for c in clients:
        cid = c["id_cliente"]
        veiculos = vmap.get(cid, [])
        if not veiculos and (c.get("carro_marca") or c.get("carro_placa")):
            veiculos = [{"id_veiculo": None, "marca": c.get("carro_marca", ""),
                         "modelo": c.get("carro_modelo", ""), "ano": c.get("carro_ano", ""),
                         "placa": c.get("carro_placa", "")}]
        c["veiculos"] = veiculos
    return render_template("clientes.html", clients=clients)


@app.route("/clientes/editar/<int:client_id>", methods=["GET", "POST"])
def editar_cliente(client_id: int):
    client = dal.get_client_by_id(client_id)
    if not client:
        flash("Cliente não encontrado.", "danger")
        return redirect(url_for("clientes"))

    if request.method == "POST":
        updates = {field: request.form.get(field, "").strip() for field in CLIENT_FIELDS}
        updates["cpf_cnpj"] = _format_cpf_cnpj(updates.get("cpf_cnpj"))
        dal.update_client(client_id, updates)
        flash("Cliente atualizado com sucesso!", "success")
        return redirect(url_for("clientes"))

    veiculos = dal.get_vehicles_by_client(client_id)
    legacy_vehicle = None
    if not veiculos and (client.get("carro_marca") or client.get("carro_modelo") or client.get("carro_placa")):
        legacy_vehicle = {
            "marca": client.get("carro_marca", ""),
            "modelo": client.get("carro_modelo", ""),
            "ano": client.get("carro_ano", ""),
            "placa": client.get("carro_placa", ""),
            "cor": "",
            "observacoes": "",
        }

    return render_template(
        "editar_cliente.html",
        client=client,
        veiculos=veiculos,
        legacy_vehicle=legacy_vehicle,
    )


@app.route("/clientes/<int:client_id>/veiculos/migrar-legado", methods=["POST"])
def migrar_veiculo_legado(client_id: int):
    client = dal.get_client_by_id(client_id)
    if not client:
        flash("Cliente não encontrado.", "danger")
        return redirect(url_for("clientes"))

    marca = request.form.get("marca", "").strip()
    modelo = request.form.get("modelo", "").strip()
    ano = request.form.get("ano", "").strip()
    placa = request.form.get("placa", "").strip()
    cor = request.form.get("cor", "").strip()
    observacoes = request.form.get("observacoes", "").strip()

    if not (marca or modelo or placa):
        flash("Não há dados de veículo legado para migrar.", "warning")
        return redirect(url_for("editar_cliente", client_id=client_id))

    dal.add_vehicle(
        {
            "id_cliente": client_id,
            "marca": marca,
            "modelo": modelo,
            "ano": ano,
            "placa": placa,
            "cor": cor,
            "observacoes": observacoes,
        }
    )

    # Limpa os campos legados para evitar duplicidade visual.
    dal.update_client(
        client_id,
        {
            "carro_marca": "",
            "carro_modelo": "",
            "carro_ano": "",
            "carro_placa": "",
        },
    )

    flash("Veículo legado convertido com sucesso. Agora ele pode ser editado ou removido.", "success")
    return redirect(url_for("editar_cliente", client_id=client_id))


@app.route("/api/clientes/<int:client_id>/veiculos")
def api_veiculos_cliente(client_id: int):
    veiculos = dal.get_vehicles_by_client(client_id)
    return jsonify(veiculos)


@app.route("/clientes/<int:client_id>/veiculos/novo", methods=["POST"])
def adicionar_veiculo(client_id: int):
    if not dal.get_client_by_id(client_id):
        flash("Cliente não encontrado.", "danger")
        return redirect(url_for("clientes"))
    marca  = request.form.get("marca",  "").strip()
    modelo = request.form.get("modelo", "").strip()
    ano    = request.form.get("ano",    "").strip()
    placa  = request.form.get("placa",  "").strip()
    cor    = request.form.get("cor",    "").strip()
    obs    = request.form.get("observacoes", "").strip()
    if not (marca or modelo or placa):
        flash("Informe ao menos marca, modelo ou placa.", "warning")
        return redirect(url_for("editar_cliente", client_id=client_id))
    dal.add_vehicle({"id_cliente": client_id, "marca": marca, "modelo": modelo,
                     "ano": ano, "placa": placa, "cor": cor, "observacoes": obs})
    flash("Veículo adicionado com sucesso!", "success")
    return redirect(url_for("editar_cliente", client_id=client_id))


@app.route("/veiculos/<int:vehicle_id>/editar", methods=["POST"])
def editar_veiculo(vehicle_id: int):
    veiculo = dal.get_vehicle_by_id(vehicle_id)
    if not veiculo:
        flash("Veículo não encontrado.", "danger")
        return redirect(url_for("clientes"))
    dal.update_vehicle(vehicle_id, {
        "marca":       request.form.get("marca",  "").strip(),
        "modelo":      request.form.get("modelo", "").strip(),
        "ano":         request.form.get("ano",    "").strip(),
        "placa":       request.form.get("placa",  "").strip(),
        "cor":         request.form.get("cor",    "").strip(),
        "observacoes": request.form.get("observacoes", "").strip(),
    })
    flash("Veículo atualizado com sucesso!", "success")
    return redirect(url_for("editar_cliente", client_id=veiculo["id_cliente"]))


@app.route("/veiculos/<int:vehicle_id>/excluir", methods=["POST"])
def excluir_veiculo(vehicle_id: int):
    veiculo = dal.get_vehicle_by_id(vehicle_id)
    if not veiculo:
        flash("Veículo não encontrado.", "danger")
        return redirect(url_for("clientes"))
    client_id = veiculo["id_cliente"]
    dal.delete_vehicle(vehicle_id)
    flash("Veículo removido.", "info")
    return redirect(url_for("editar_cliente", client_id=client_id))


@app.route("/clientes/<int:client_id>/historico")
def historico_cliente(client_id: int):
    client = dal.get_client_by_id(client_id)
    if not client:
        flash("Cliente não encontrado.", "danger")
        return redirect(url_for("clientes"))

    data_inicio = request.args.get("data_inicio")
    data_fim = request.args.get("data_fim")

    services_df = dal.get_all_services()
    services_df = services_df[services_df["id_cliente"] == client_id]
    services_df["data_execucao"] = pd.to_datetime(services_df["data_execucao"], errors="coerce")

    if data_inicio:
        services_df = services_df[services_df["data_execucao"] >= _parse_date(data_inicio)]
    if data_fim:
        services_df = services_df[services_df["data_execucao"] <= _parse_date(data_fim)]

    services_df = services_df.sort_values("data_execucao", ascending=False)
    services = []
    for row in services_df.to_dict(orient="records"):
        row["data_formatada"] = _format_date(row.get("data_execucao"))
        services.append(row)

    return render_template(
        "historico_cliente.html",
        client=client,
        services=services,
        data_inicio=data_inicio,
        data_fim=data_fim,
    )


@app.route("/meus-servicos")
def meus_servicos():
    """Tela pessoal: serviços realizados pelo usuário logado."""
    nome_logado = session.get("user_name") or ""
    nome_normalizado = _normalize_person_name(nome_logado)

    services_df = dal.get_all_services()
    if "responsavel" not in services_df.columns:
        services_df["responsavel"] = ""

    services_df["responsavel_norm"] = (
        services_df["responsavel"].fillna("").astype(str).apply(_normalize_person_name)
    )
    mine_df = services_df[services_df["responsavel_norm"] == nome_normalizado].copy()

    mine_df["data_execucao_dt"] = pd.to_datetime(mine_df["data_execucao"], errors="coerce")
    mine_df["valor_num"] = pd.to_numeric(mine_df.get("valor"), errors="coerce").fillna(0)

    today = datetime.today()
    month_mask = (
        (mine_df["data_execucao_dt"].dt.month == today.month)
        & (mine_df["data_execucao_dt"].dt.year == today.year)
    )

    total_servicos = int(len(mine_df))
    servicos_mes = int(month_mask.sum())
    valor_total = float(mine_df["valor_num"].sum())
    valor_mes = float(mine_df.loc[month_mask, "valor_num"].sum())

    clients_df = dal.get_all_clients().fillna("")
    clients_lookup = {
        _coerce_int(row.get("id_cliente")): row.get("nome", "")
        for row in clients_df.to_dict(orient="records")
    }

    services_list = []
    for row in mine_df.sort_values("data_execucao_dt", ascending=False).to_dict(orient="records"):
        services_list.append({
            "id_servico": row.get("id_servico"),
            "id_orcamento": row.get("id_orcamento"),
            "ordem_servico": row.get("ordem_servico") or "",
            "id_cliente": row.get("id_cliente"),
            "cliente_nome": clients_lookup.get(_coerce_int(row.get("id_cliente")), "Cliente removido"),
            "data_formatada": _format_date(row.get("data_execucao")),
            "descricao": row.get("descricao_servico") or "-",
            "tipo": row.get("tipo_servico") or "-",
            "valor": float(row.get("valor_num") or 0),
        })

    clients_df = dal.get_all_clients().fillna("")
    clients = clients_df.to_dict(orient="records")
    return render_template(
        "meus_servicos.html",
        nome_logado=nome_logado,
        total_servicos=total_servicos,
        servicos_mes=servicos_mes,
        valor_total=valor_total,
        valor_mes=valor_mes,
        services=services_list,
        clients=clients,
        mes_atual=MONTH_NAMES[today.month - 1],
        ano_atual=today.year,
    )


@app.route("/meus-servicos/registrar", methods=["POST"])
def registrar_servico():
    nome_logado = session.get("user_name") or ""
    if not nome_logado:
        flash("É necessário estar logado para registrar um serviço.", "danger")
        return redirect(url_for("meus_servicos"))

    try:
        id_cliente = int(request.form.get("id_cliente", ""))
    except (TypeError, ValueError):
        id_cliente = None

    if not id_cliente:
        flash("Selecione um cliente para o serviço.", "warning")
        return redirect(url_for("meus_servicos"))
    cliente = dal.get_client_by_id(id_cliente)
    if not cliente:
        flash("Cliente selecionado não encontrado.", "danger")
        return redirect(url_for("meus_servicos"))
    descricoes = request.form.getlist("descricao_servico[]") or [request.form.get("descricao_servico", "")]
    tipos = request.form.getlist("tipo_servico[]") or [request.form.get("tipo_servico", "")]
    valores = request.form.getlist("valor[]") or [request.form.get("valor", "")]
    observacoes_list = request.form.getlist("observacoes[]") or [request.form.get("observacoes", "")]

    service_items = []
    for index, (descricao_raw, tipo_raw, valor_raw) in enumerate(zip(descricoes, tipos, valores), start=1):
        descricao = (descricao_raw or "").strip()
        tipo = (tipo_raw or "").strip()
        valor_text = (valor_raw or "").strip()
        observacoes = (
            observacoes_list[index - 1].strip()
            if index - 1 < len(observacoes_list) and observacoes_list[index - 1]
            else ""
        )
        if not descricao and not tipo and not valor_text:
            continue
        if not descricao:
            flash(f"Informe a descrição do serviço {index}.", "warning")
            return redirect(url_for("meus_servicos"))
        if not tipo:
            flash(f"Informe o tipo do serviço {index}.", "warning")
            return redirect(url_for("meus_servicos"))
        try:
            valor = _parse_brl_number(valor_text)
        except ValueError:
            flash(f"Informe um valor válido para o serviço {index}.", "warning")
            return redirect(url_for("meus_servicos"))
        service_items.append({
            "descricao": descricao,
            "tipo": tipo,
            "valor": round(valor, 2),
            "observacoes": observacoes,
        })

    if not service_items:
        flash("Inclua pelo menos um serviço.", "warning")
        return redirect(url_for("meus_servicos"))

    ordem_servico = _generate_service_order_number()
    for item in service_items:
        dal.add_service({
            "id_cliente": id_cliente,
            "data_execucao": datetime.today().strftime("%Y-%m-%d"),
            "descricao_servico": item["descricao"],
            "tipo_servico": item["tipo"],
            "valor": item["valor"],
            "observacoes": item["observacoes"],
            "responsavel": nome_logado,
            "status": "Pendente",
            "ordem_servico": ordem_servico,
        })
    flash(
        f"{len(service_items)} serviço(s) registrado(s) na OS {ordem_servico}. Aguarde a conferência administrativa.",
        "success",
    )
    return redirect(url_for("meus_servicos"))


@app.route("/servicos/<int:service_id>/finalizar", methods=["GET", "POST"])
@require_admin
def finalizar_servico(service_id: int):
    service = dal.get_service_by_id(service_id)
    if not service:
        flash("Serviço não encontrado.", "danger")
        return redirect(url_for("historico_servicos"))
    services_group = _get_service_group(service)
    primary_service = services_group[0] if services_group else service
    service_ids = [s.get("id_servico") for s in services_group if s.get("id_servico")]
    service_ref = _service_order_label(primary_service)

    cliente = None
    if primary_service.get("id_cliente") is not None:
        cliente = dal.get_client_by_id(int(primary_service["id_cliente"]))
    if not cliente:
        flash("Cliente associado ao serviço não foi encontrado.", "warning")
        return redirect(url_for("historico_servicos"))

    if request.method == "POST":
        posted_ids = request.form.getlist("service_id[]")
        descricoes = request.form.getlist("descricao_servico[]") or [request.form.get("descricao_servico", "")]
        tipos = request.form.getlist("tipo_servico[]") or [request.form.get("tipo_servico", "")]
        valores = request.form.getlist("valor[]") or [request.form.get("valor", "")]
        observacoes_list = request.form.getlist("observacoes[]") or [request.form.get("observacoes", "")]
        produto_descricao = request.form.get("produto_descricao", "").strip()
        produto_valor_raw = request.form.get("produto_valor", "").strip()
        forma_pagamento = request.form.get("forma_pagamento", "PIX")
        data_conclusao = request.form.get("data_conclusao", datetime.today().strftime("%Y-%m-%d"))

        if forma_pagamento not in PAYMENT_OPTIONS:
            flash("Escolha uma forma de pagamento válida.", "warning")
            return redirect(url_for("finalizar_servico", service_id=service_id))

        services_to_update = []
        for index, (descricao_raw, tipo_raw, valor_raw) in enumerate(zip(descricoes, tipos, valores), start=1):
            descricao = (descricao_raw or "").strip()
            tipo = (tipo_raw or "").strip()
            valor_text = (valor_raw or "").strip()
            observacoes = (
                observacoes_list[index - 1].strip()
                if index - 1 < len(observacoes_list) and observacoes_list[index - 1]
                else ""
            )
            service_id_raw = posted_ids[index - 1] if index - 1 < len(posted_ids) else ""
            sid = _coerce_int(service_id_raw) or (service_ids[index - 1] if index - 1 < len(service_ids) else None)
            if not sid:
                continue
            if not descricao:
                flash(f"Informe a descrição do serviço {index}.", "warning")
                return redirect(url_for("finalizar_servico", service_id=service_id))
            if not tipo:
                flash(f"Informe o tipo do serviço {index}.", "warning")
                return redirect(url_for("finalizar_servico", service_id=service_id))
            try:
                valor = _parse_brl_number(valor_text)
            except ValueError:
                flash(f"Informe um valor válido para o serviço {index}.", "warning")
                return redirect(url_for("finalizar_servico", service_id=service_id))
            services_to_update.append({
                "id_servico": sid,
                "descricao_servico": descricao,
                "tipo_servico": tipo,
                "valor": round(valor, 2),
                "observacoes": observacoes,
            })
        if not services_to_update:
            flash("Inclua pelo menos um serviço para finalizar.", "warning")
            return redirect(url_for("finalizar_servico", service_id=service_id))
        try:
            produto_valor = _parse_brl_number(produto_valor_raw)
        except ValueError:
            flash("Informe um valor válido para o custo da peça.", "warning")
            return redirect(url_for("finalizar_servico", service_id=service_id))

        valor_servicos = round(sum(item["valor"] for item in services_to_update), 2)
        valor_final = round(valor_servicos + produto_valor, 2)
        data_obj = _parse_date(data_conclusao)
        if not data_obj:
            flash("Informe uma data de conclusão válida.", "warning")
            return redirect(url_for("finalizar_servico", service_id=service_id))

        for index, item in enumerate(services_to_update):
            payload = {
                "descricao_servico": item["descricao_servico"],
                "tipo_servico": item["tipo_servico"],
                "valor": item["valor"],
                "observacoes": item["observacoes"],
                "status": "Concluído",
                "data_execucao": data_obj.strftime("%Y-%m-%d"),
            }
            if index == 0:
                payload["produto_descricao"] = produto_descricao
                payload["produto_valor"] = round(produto_valor, 2) if produto_valor else None
            else:
                payload["produto_descricao"] = ""
                payload["produto_valor"] = None
            dal.update_service(item["id_servico"], payload)

        existing_financial_df = dal.get_all_financial_entries()
        has_entry = False
        if not existing_financial_df.empty:
            related_service = pd.to_numeric(
                existing_financial_df.get("relacionado_servico_id"), errors="coerce"
            )
            has_entry = (related_service.isin(service_ids) &
                         (existing_financial_df["tipo_lancamento"].fillna("").astype(str).str.lower() == "entrada")).any()

        if not has_entry:
            dal.add_financial_entry({
                "data": data_obj.strftime("%Y-%m-%d"),
                "tipo_lancamento": "Entrada",
                "categoria": "Serviços prestados",
                "descricao": f"OS {service_ref} - {cliente.get('nome', '')}",
                "valor": valor_final,
                "relacionado_orcamento_id": None,
                "relacionado_servico_id": service_id,
            })

        if produto_descricao and produto_valor > 0:
            has_exit_entry = False
            if not existing_financial_df.empty:
                related_service = pd.to_numeric(
                    existing_financial_df.get("relacionado_servico_id"), errors="coerce"
                )
                desc_col = existing_financial_df["descricao"].fillna("").astype(str)
                has_exit_entry = (
                    related_service.isin(service_ids)
                    & (existing_financial_df["tipo_lancamento"].fillna("").astype(str).str.lower() == "saída")
                    & desc_col.str.contains(re.escape(produto_descricao), case=False, na=False)
                ).any()
            if not has_exit_entry:
                dal.add_financial_entry({
                    "data": data_obj.strftime("%Y-%m-%d"),
                    "tipo_lancamento": "Saída",
                    "categoria": "Materiais e peças - Componentes automotivos",
                    "descricao": f"{produto_descricao} - OS {service_ref}",
                    "valor": round(produto_valor, 2),
                    "relacionado_orcamento_id": None,
                    "relacionado_servico_id": service_id,
                })

        texto_whatsapp = _generate_service_payment_whatsapp_text(
            cliente.get("nome", "cliente"),
            service_ref,
            valor_final,
            data_obj,
        )
        whatsapp_url = _build_whatsapp_url(cliente.get("telefone_whatsapp", ""), texto_whatsapp)

        items = [
            {
                "descricao": item["descricao_servico"],
                "quantidade": 1,
                "valor_unitario": item["valor"],
                "subtotal": item["valor"],
            }
            for item in services_to_update
        ]
        if produto_descricao and produto_valor > 0:
            items.append({
                "descricao": produto_descricao,
                "quantidade": 1,
                "valor_unitario": round(produto_valor, 2),
                "subtotal": round(produto_valor, 2),
            })

        return render_template(
            "pagamento_concluido.html",
            entity_label="OS",
            entity_id=service_ref,
            budget_id=None,
            client=cliente,
            items=items,
            valor_final=valor_final,
            data_pagamento=data_obj,
            texto_whatsapp=texto_whatsapp,
            whatsapp_url=whatsapp_url,
            receipt_url=url_for("gerar_recibo_servico", service_id=service_id),
            details_url=url_for("historico_servicos"),
        )

    return render_template(
        "finalizar_servico.html",
        service=primary_service,
        services=services_group,
        service_ref=service_ref,
        client=cliente,
        payment_options=PAYMENT_OPTIONS,
        today_str=datetime.today().strftime("%Y-%m-%d"),
        taxa_cartao=TAXA_CARTAO_CREDITO,
    )


@app.route("/funcionarios", methods=["GET", "POST"])
@require_admin
def funcionarios():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        if not nome:
            flash("Informe o nome do funcionário.", "warning")
            return redirect(url_for("funcionarios"))

        duplicate = _find_employee_duplicate(nome)
        if duplicate:
            _flash_employee_duplicate(duplicate)
            return redirect(url_for("funcionarios"))

        access_payload, access_error = _build_employee_access_payload(request.form)
        if access_error:
            flash(access_error, "warning")
            return redirect(url_for("funcionarios"))

        payload = {field: request.form.get(field, "").strip() for field in EMPLOYEE_FIELDS}
        payload["ativo"] = True
        payload.update(access_payload)
        dal.add_employee(payload)
        flash("Funcionário cadastrado com sucesso.", "success")
        return redirect(url_for("funcionarios"))

    employees_df = dal.get_all_employees().fillna("")
    employees = employees_df.to_dict(orient="records")
    return render_template("funcionarios.html", employees=employees)


@app.route("/funcionarios/deduplicar", methods=["POST"])
@require_admin
def deduplicar_funcionarios():
    removed = dal.deduplicate_employees()
    if removed:
        flash(f"{removed} registro(s) duplicado(s) removido(s) com sucesso.", "success")
    else:
        flash("Nenhum duplicado encontrado.", "info")
    return redirect(url_for("funcionarios"))


@app.route("/funcionarios/<int:employee_id>/editar", methods=["POST"])
@require_admin
def editar_funcionario(employee_id: int):
    employee = dal.get_employee_by_id(employee_id)
    if not employee:
        flash("Funcionário não encontrado.", "danger")
        return redirect(url_for("funcionarios"))
    payload = {field: request.form.get(field, "").strip() for field in EMPLOYEE_FIELDS}
    if not payload.get("nome"):
        flash("Informe o nome do funcionário.", "warning")
        return redirect(url_for("funcionarios"))
    duplicate = _find_employee_duplicate(payload["nome"], ignore_employee_id=employee_id)
    if duplicate:
        _flash_employee_duplicate(duplicate)
        return redirect(url_for("funcionarios"))

    access_payload, access_error = _build_employee_access_payload(request.form, existing=employee)
    if access_error:
        flash(access_error, "warning")
        return redirect(url_for("funcionarios"))
    is_editing_self = session.get("user_id") == employee_id
    if is_editing_self and _normalize_role(access_payload.get("perfil")) != ROLE_ADMIN:
        flash("Você não pode remover seu próprio perfil de administrador.", "warning")
        return redirect(url_for("funcionarios"))
    payload.update(access_payload)

    dal.update_employee(employee_id, payload)
    flash("Dados do funcionário atualizados com sucesso.", "success")
    return redirect(url_for("funcionarios"))


@app.route("/funcionarios/<int:employee_id>/toggle", methods=["POST"])
@require_admin
def toggle_funcionario(employee_id: int):
    employee = dal.get_employee_by_id(employee_id)
    if not employee:
        flash("Funcionário não encontrado.", "danger")
        return redirect(url_for("funcionarios"))
    if session.get("user_id") == employee_id:
        flash("Você não pode inativar o próprio usuário administrador.", "warning")
        return redirect(url_for("funcionarios"))
    current = str(employee.get("ativo", "")).strip().lower()
    is_active = current not in {"false", "0", "nao", "não"}
    dal.update_employee(employee_id, {"ativo": not is_active})
    flash("Status do funcionário atualizado.", "info")
    return redirect(url_for("funcionarios"))


@app.route("/historico-servicos")
def historico_servicos():
    """Tela consolidada de serviços com filtro por cliente e placa."""
    selected_client_id = request.args.get("cliente")
    selected_placa = request.args.get("placa", "").strip().upper()
    try:
        selected_client_id = int(selected_client_id) if selected_client_id else None
    except ValueError:
        flash("Seleção de cliente inválida.", "danger")
        return redirect(url_for("historico_servicos"))

    services_df = dal.get_all_services()
    clients_df = dal.get_all_clients()[["id_cliente", "nome"]]
    budgets_df = dal.get_all_budgets()[["id_orcamento", "status", "carro_km", "id_veiculo"]].rename(
        columns={"status": "budget_status"}
    )

    # Busca dados do veículo (placa, marca, modelo) via id_veiculo do orçamento
    vehicles_df = pd.DataFrame(dal.get_all_vehicles())
    if not vehicles_df.empty:
        vehicles_df = vehicles_df[["id_veiculo", "marca", "modelo", "placa"]].fillna("")
        budgets_df = budgets_df.merge(vehicles_df, on="id_veiculo", how="left")
    else:
        budgets_df["marca"] = ""
        budgets_df["modelo"] = ""
        budgets_df["placa"] = ""

    services_df = services_df.merge(clients_df, on="id_cliente", how="left")
    services_df = services_df.merge(budgets_df, on="id_orcamento", how="left")
    services_df["data_execucao"] = pd.to_datetime(
        services_df["data_execucao"], errors="coerce"
    )
    services_df = services_df.fillna("")

    if selected_client_id:
        services_df = services_df[services_df["id_cliente"] == selected_client_id]

    if selected_placa:
        services_df = services_df[
            services_df["placa"].astype(str).str.upper().str.contains(selected_placa, na=False)
        ]

    services_df = services_df.sort_values("data_execucao", ascending=False)

    # Mantém serviço direto e orçamento como fluxos separados:
    # - serviço direto: OS já realizada, sem orçamento/cliente aprovar
    # - orçamento: proposta que passa por aprovação e efetivação
    direct_seen: dict = {}
    direct_order: list = []
    budgets_seen: dict = {}
    budgets_order: list = []
    for row in services_df.to_dict(orient="records"):
        ordem_servico = str(row.get("ordem_servico") or "").strip()
        budget_id = _coerce_int(row.get("id_orcamento"))
        display_status = row.get("budget_status") if budget_id else row.get("status")
        if budget_id:
            key = budget_id
            target_seen = budgets_seen
            target_order = budgets_order
        else:
            key = f"os_{ordem_servico}" if ordem_servico else f"sem_{row.get('id_servico')}"
            target_seen = direct_seen
            target_order = direct_order

        if key not in target_seen:
            marca = str(row.get("marca") or "").strip()
            modelo = str(row.get("modelo") or "").strip()
            placa = str(row.get("placa") or "").strip()
            veiculo_info = " ".join(p for p in [marca, modelo] if p) or "-"
            if placa:
                veiculo_info += f" ({placa})"
            target_seen[key] = {
                "budget_id": budget_id,
                "service_id": row.get("id_servico"),
                "order_number": ordem_servico,
                "client_id": row.get("id_cliente"),
                "client_name": row.get("nome") or "N/D",
                "service_date": _format_date(row.get("data_execucao")),
                "carro_km": row.get("carro_km") or "-",
                "veiculo_info": veiculo_info,
                "placa": placa or "-",
                "status": display_status or "Sem status",
                "total_value": 0.0,
                "itens": [],
            }
            target_order.append(key)

        entry = target_seen[key]
        if _normalize_status(display_status) == "pendente":
            entry["status"] = display_status or entry["status"]
        entry["total_value"] = round(entry["total_value"] + float(row.get("valor") or 0), 2)
        entry["itens"].append({
            "tipo":        row.get("tipo_servico") or "-",
            "descricao":   row.get("descricao_servico") or "-",
            "valor":       float(row.get("valor") or 0),
            "responsavel": row.get("responsavel") or "-",
            "observacoes": row.get("observacoes") or "-",
        })

    services = [budgets_seen[k] for k in budgets_order]
    direct_services = [direct_seen[k] for k in direct_order]

    # Apenas clientes com serviços, em ordem alfabética
    all_services_df = dal.get_all_services().merge(clients_df, on="id_cliente", how="left")
    client_ids_with_services = set(
        all_services_df["id_cliente"].dropna().astype(int).tolist()
    )
    clients = (
        clients_df[clients_df["id_cliente"].isin(client_ids_with_services)]
        .sort_values("nome")
        .to_dict(orient="records")
    )

    # Placas únicas disponíveis para o filtro (considerando cliente selecionado)
    placas_df = budgets_df.copy()
    if selected_client_id:
        ids_with_client = all_services_df[
            all_services_df["id_cliente"] == selected_client_id
        ]["id_orcamento"].dropna().unique()
        placas_df = placas_df[placas_df["id_orcamento"].isin(ids_with_client)]
    placas = sorted(
        p for p in placas_df["placa"].dropna().astype(str).str.strip().unique() if p
    )

    return render_template(
        "historico_servicos.html",
        services=services,
        direct_services=direct_services,
        clients=clients,
        selected_client_id=selected_client_id,
        selected_placa=selected_placa,
        placas=placas,
    )


def _build_budget_items_from_form(form) -> List[dict]:
    descricoes = form.getlist("item_descricao[]")
    tipos = form.getlist("item_tipo[]")
    quantidades = form.getlist("item_quantidade[]")
    valores = form.getlist("item_valor[]")
    custos = form.getlist("item_custo[]")

    items = []
    for i, (desc, tipo, qtd, val) in enumerate(zip(descricoes, tipos, quantidades, valores)):
        if not desc:
            continue
        try:
            quantidade = float(qtd or 1)
        except (TypeError, ValueError):
            quantidade = 1.0
        try:
            valor_unitario = _parse_brl_number(val or "0")
        except (TypeError, ValueError):
            valor_unitario = 0.0
        try:
            custo_unitario = _parse_brl_number(custos[i]) if i < len(custos) and custos[i].strip() else 0.0
        except (TypeError, ValueError):
            custo_unitario = 0.0
        items.append(
            {
                "descricao": desc.strip(),
                "tipo": tipo.strip(),
                "quantidade": quantidade,
                "valor_unitario": valor_unitario,
                "subtotal": quantidade * valor_unitario,
                "custo_unitario": custo_unitario,
                "custo_total": quantidade * custo_unitario,
            }
        )
    return items


# ---------------------------
# Funções auxiliares de apresentação
# ---------------------------
def _calculate_total_with_payment(base_total: float, payment_method: str) -> Tuple[float, float]:
    """Retorna (total_final, taxa) aplicando regras da forma de pagamento."""
    total = base_total
    taxa = 0.0
    if payment_method == "Cartão Crédito":
        taxa = round(base_total * TAXA_CARTAO_CREDITO, 2)
        total = round(base_total + taxa, 2)
    return total, taxa


def _generate_whatsapp_text(
    client_name: str,
    items: List[dict],
    total: float,
    payment_method: str,
    taxa: float,
) -> str:
    base_total = sum(float(item.get("subtotal", 0) or 0) for item in items)
    linhas = [
        f"Olá {client_name}, tudo bem?",
        f"Segue abaixo o orçamento detalhado da oficina {COMPANY_INFO['razao_social']}:",
        "",
    ]
    for item in items:
        linhas.append(
            f"- {item['descricao']} ({item['quantidade']}x R$ {item['valor_unitario']:.2f}) = R$ {item['subtotal']:.2f}"
        )
    linhas.extend(["", f"Forma de pagamento: {payment_method}"])
    if taxa > 0:
        linhas.extend(
            [
                f"Valor dos itens (sem taxa): {dal.format_currency(base_total)}",
                f"Taxa cartão de crédito (3%): {dal.format_currency(taxa)}",
                f"Valor final a pagar: {dal.format_currency(total)}",
            ]
        )
    else:
        linhas.append(f"Valor total: {dal.format_currency(total)}")

    linhas.extend(
        [
            "Validade do orçamento: 5 dias corridos.",
            "Prazo estimado para execução: conforme disponibilidade na agenda.",
            "Qualquer dúvida é só me chamar!",
        ]
    )
    return "\n".join(linhas)



def _generate_budget_pdf(budget: dict, client: dict, items: List[dict], veiculo: Optional[dict] = None) -> BytesIO:
    """Gera o PDF de orçamento no layout do modelo fornecido."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    yellow = (244, 195, 28)
    dark_blue = (26, 55, 102)
    light_gray = (230, 230, 230)
    text_gray = (90, 90, 90)

    # Faixas decorativas inspiradas no template.
    pdf.set_fill_color(*yellow)
    pdf.rect(-5, -5, 90, 18, "F")
    pdf.rect(150, 285, 70, 15, "F")

    # Logo centralizada.
    logo_path = _get_pdf_logo_path()
    y_after_logo = 16
    if logo_path:
        try:
            pdf.image(logo_path, x=85, y=16, w=40, h=32)
            y_after_logo = 16 + 32
        except RuntimeError:
            y_after_logo = 20

    # Contatos no topo direito.
    pdf.set_xy(135, 14)
    pdf.set_font("Arial", "", 10)
    pdf.set_text_color(*dark_blue)
    contact_lines = [COMPANY_INFO.get("telefone", "")]
    email = COMPANY_INFO.get("email")
    if email:
        contact_lines.append(email)
    pdf.multi_cell(60, 5, _pdf_safe_text("\n".join(line for line in contact_lines if line)), align="R")

    # Título.
    pdf.set_y(max(y_after_logo + 6, 50))
    pdf.set_font("Arial", "B", 26)
    pdf.set_text_color(*dark_blue)
    pdf.cell(0, 12, "ORÇAMENTO", ln=1, align="C")

    base_total = sum(float(item.get("subtotal", 0) or 0) for item in items)
    forma_pagamento = budget.get("forma_pagamento") or "PIX"
    final_total = float(budget.get("valor_total", base_total) or base_total)
    taxa_pagamento = max(0.0, round(final_total - base_total, 2))

    # Barra de dados da loja.
    pdf.ln(6)
    info_rows = [
        ("Razão Social", COMPANY_INFO.get("razao_social", "")),
        ("CNPJ", COMPANY_INFO.get("cnpj", "")),
        ("Endereço", COMPANY_INFO.get("endereco", "")),
        ("Telefone", COMPANY_INFO.get("telefone", "")),
    ]
    row_y = pdf.get_y()
    for label, value in info_rows:
        pdf.set_fill_color(*light_gray)
        pdf.rect(10, row_y, 190, 12, "F")
        pdf.set_xy(14, row_y + 3.5)
        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(*dark_blue)
        pdf.cell(0, 0, _pdf_safe_text(label.upper()))
        pdf.set_xy(70, row_y + 2.5)
        pdf.set_font("Arial", "B", 11)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 0, _pdf_safe_text(value))
        row_y += 14
    pdf.set_y(row_y + 4)

    # Tabela de itens.
    headers = [
        ("ITEM", 18),
        ("DESCRIÇÃO", 84),
        ("QUANT.", 20),
        ("UNITÁRIO", 32),
        ("TOTAL", 36),
    ]
    pdf.set_fill_color(*yellow)
    pdf.set_text_color(*dark_blue)
    pdf.set_font("Arial", "B", 11)
    for header, width in headers:
        pdf.cell(width, 9, header, border=1, align="C", fill=True)
    pdf.ln()

    pdf.set_text_color(*text_gray)
    pdf.set_font("Arial", "", 10)
    pdf.set_draw_color(200, 200, 200)
    min_rows = max(len(items), 6)
    for idx in range(min_rows):
        if idx < len(items):
            item = items[idx]
            descricao = _pdf_safe_text(item.get("descricao") or f"Serviço {idx + 1}")
            quantidade_raw = item.get("quantidade", 1)
            quantidade_display = _format_quantity_display(quantidade_raw)
            try:
                quantidade_num = float(quantidade_raw)
            except (TypeError, ValueError):
                quantidade_num = 1.0
            valor_unitario = float(item.get("valor_unitario", 0) or 0)
            subtotal = float(item.get("subtotal", valor_unitario * quantidade_num))
            row_values = [
                str(idx + 1),
                descricao,
                quantidade_display,
                dal.format_currency(valor_unitario),
                dal.format_currency(subtotal),
            ]
        else:
            row_values = ["", "", "", "", ""]

        for (label, width), value in zip(headers, row_values):
            align = "C" if label in {"ITEM", "QUANT.", "UNITÁRIO", "TOTAL"} else "L"
            pdf.cell(width, 9, _pdf_safe_text(value), border=1, align=align)
        pdf.ln()

    pdf.set_fill_color(*yellow)
    pdf.set_text_color(*dark_blue)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(sum(width for _, width in headers[:-1]), 9, "TOTAL:", border=1, align="R", fill=True)
    pdf.cell(headers[-1][1], 9, dal.format_currency(final_total), border=1, align="C", fill=True)
    pdf.ln(12)

    pdf.set_text_color(*text_gray)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 6, _pdf_safe_text(f"Forma de pagamento: {forma_pagamento}"), ln=1)
    if taxa_pagamento > 0:
        pdf.cell(0, 6, _pdf_safe_text(f"Valor dos itens (sem taxa): {dal.format_currency(base_total)}"), ln=1)
        pdf.cell(0, 6, _pdf_safe_text(f"Taxa cartão de crédito (3%): {dal.format_currency(taxa_pagamento)}"), ln=1)
        pdf.cell(0, 6, _pdf_safe_text(f"Valor final a pagar: {dal.format_currency(final_total)}"), ln=1)
        pdf.ln(4)

    # Informações complementares.
    pdf.set_text_color(*dark_blue)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 7, "DATA:", ln=1)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 7, _format_date(budget.get("data_criacao")), ln=1)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 7, "VALIDADE DO DOCUMENTO:", ln=1)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 7, VALIDADE_PADRAO, ln=1)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 7, "OBSERVAÇÕES:", ln=1)
    pdf.set_font("Arial", "", 11)
    responsavel_nome = budget.get("responsavel_planejado_nome") or ""
    observacoes_texto = OBSERVACOES_PADRAO
    if responsavel_nome:
        observacoes_texto += f"\nServiço planejado para: {responsavel_nome}"
    pdf.multi_cell(0, 6, observacoes_texto)

    pdf.ln(4)
    pdf.set_font("Arial", "", 10)
    pdf.set_text_color(*text_gray)
    pdf.multi_cell(0, 5, _pdf_safe_text(COMPANY_INFO.get("endereco", "")))

    pdf_output = pdf.output(dest="S").encode("latin-1")
    buffer = BytesIO(pdf_output)
    buffer.seek(0)
    return buffer


def _generate_receipt_pdf(
    budget_id: int,
    budget: dict,
    client: dict,
    items: List[dict],
    valor_final: float,
    data_conclusao: datetime,
    responsavel_execucao: str = "",
    veiculo: Optional[dict] = None,
) -> BytesIO:
    """Gera um recibo baseado nos dados do orçamento e pagamento."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    yellow = (244, 195, 28)
    dark_blue = (26, 55, 102)
    gray = (200, 200, 200)

    header_top = 14
    logo_w = 26
    logo_h = 26
    logo_bottom = header_top + logo_h

    logo_path = _get_pdf_logo_path()
    if logo_path:
        try:
            pdf.image(logo_path, x=12, y=header_top, w=logo_w, h=logo_h)
        except RuntimeError:
            logo_bottom = header_top + 4

    text_x = 50
    block_w = 95
    pdf.set_font("Arial", "B", 12)
    pdf.set_text_color(*dark_blue)
    pdf.set_xy(text_x, header_top)
    pdf.cell(block_w, 6, _pdf_safe_text(COMPANY_INFO.get("razao_social", "")), ln=1)

    pdf.set_font("Arial", "", 10)
    pdf.set_x(text_x)
    pdf.cell(block_w, 5, f"CNPJ: {_pdf_safe_text(COMPANY_INFO.get('cnpj', ''))}", ln=1)
    pdf.set_x(text_x)
    pdf.cell(block_w, 5, _pdf_safe_text(COMPANY_INFO.get("telefone", "")), ln=1)
    email_line = COMPANY_INFO.get("email", "")
    if email_line:
        pdf.set_x(text_x)
        pdf.cell(block_w, 5, f"Email: {_pdf_safe_text(email_line)}", ln=1)
    pdf.set_x(text_x)
    pdf.cell(block_w, 5, _pdf_safe_text(COMPANY_INFO.get("endereco", "")), ln=1)
    text_bottom = pdf.get_y()

    pdf.set_xy(150, header_top)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(40, 8, f"RECIBO Nº: {budget_id}", border=1, align="C", ln=1)
    header_bottom = max(logo_bottom, text_bottom, pdf.get_y())

    # Bloco de informações do cliente.
    pdf.set_y(header_bottom + 12)
    pdf.set_fill_color(*gray)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 8, "INFORMAÇÕES DO CLIENTE", ln=1, align="C", fill=True)
    pdf.set_font("Arial", "", 10)
    pdf.set_draw_color(80, 80, 80)

    table_x = 10
    table_w = 190
    row_h = 9
    label_w = 24

    def row_two(left_label, left_value, right_label, right_value):
        pdf.rect(table_x, pdf.get_y(), table_w, row_h)
        pdf.rect(table_x, pdf.get_y(), table_w / 2, row_h)
        pdf.rect(table_x + table_w / 2, pdf.get_y(), table_w / 2, row_h)

        pdf.set_xy(table_x + 2, pdf.get_y() + 2)
        pdf.set_font("Arial", "B", 9)
        pdf.cell(label_w, 5, _pdf_safe_text(f"{left_label}:"))
        pdf.set_font("Arial", "", 9)
        pdf.cell(table_w / 2 - label_w - 4, 5, _pdf_safe_text(left_value))

        pdf.set_xy(table_x + table_w / 2 + 2, pdf.get_y())
        pdf.set_font("Arial", "B", 9)
        pdf.cell(label_w, 5, _pdf_safe_text(f"{right_label}:"))
        pdf.set_font("Arial", "", 9)
        pdf.cell(table_w / 2 - label_w - 4, 5, _pdf_safe_text(right_value))
        pdf.ln(row_h)

    def row_three(a_label, a_val, b_label, b_val, c_label, c_val):
        col_w = table_w / 3
        y_start = pdf.get_y()
        for idx, (label, value) in enumerate(
            [(a_label, a_val), (b_label, b_val), (c_label, c_val)]
        ):
            x = table_x + idx * col_w
            pdf.rect(x, y_start, col_w, row_h)
            pdf.set_xy(x + 2, y_start + 2)
            pdf.set_font("Arial", "B", 9)
            pdf.cell(label_w, 5, _pdf_safe_text(f"{label}:"))
            pdf.set_font("Arial", "", 9)
            pdf.cell(col_w - label_w - 4, 5, _pdf_safe_text(value))
        pdf.ln(row_h)

    v = veiculo or {}
    carro_cor = budget.get("carro_cor") or v.get("cor", "")
    carro_km  = budget.get("carro_km") or ""

    row_two("CLIENTE", client.get("nome", ""), "VEICULO", v.get("modelo", ""))
    row_two("MARCA", v.get("marca", ""), "PLACA", v.get("placa", ""))
    row_three("ANO", v.get("ano", ""), "COR", carro_cor, "KM", carro_km)

    # Descrição principal.
    pdf.ln(8)
    descricao_itens = "; ".join(
        f"{item.get('descricao', 'Item')} ({item.get('quantidade', 1)}x {dal.format_currency(item.get('valor_unitario', 0))})"
        for item in items
    )
    descricao_texto = (
        f'Recebi(emos) de {_pdf_safe_text(client.get("nome", "cliente não informado"))}, '
        f'a quantia de {dal.format_currency(valor_final)}, referente aos serviços/itens: {descricao_itens or "Itens do orçamento"}. '
        f'Orçamento #{budget_id} concluído em {_format_date(data_conclusao)}.'
    )
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 6, _pdf_safe_text(descricao_texto), border=1)

    # Observações.
    pdf.ln(4)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(0, 6, "OBSERVAÇÕES.", ln=1)
    obs_text = "-"
    if responsavel_execucao:
        obs_text = f"Serviço realizado por: {responsavel_execucao}"
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 6, _pdf_safe_text(obs_text), border=1)

    # Assinatura / selo pago.
    pdf.ln(6)
    pdf.set_font("Arial", "", 9)
    pdf.cell(0, 5, f"Data: {_format_date(data_conclusao)}", ln=1, align="R")
    pdf.cell(0, 5, f"Hora: {datetime.now().strftime('%H:%M:%S')}", ln=1, align="R")

    pdf.ln(6)
    pdf.set_fill_color(220, 60, 60)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(25, 10, "PAGO", border=1, align="C", fill=True)

    pdf.set_xy(40, pdf.get_y() - 2)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(0, 6, _pdf_safe_text(COMPANY_INFO.get("razao_social", "")), ln=1)
    pdf.set_font("Arial", "", 9)
    pdf.set_xy(40, pdf.get_y())
    pdf.cell(0, 6, f"CNPJ: {_pdf_safe_text(COMPANY_INFO.get('cnpj', ''))}", ln=1)

    pdf.set_y(pdf.get_y() + 6)
    pdf.set_font("Arial", "I", 9)
    pdf.cell(0, 6, "Manaus - AM", ln=1, align="C")
    pdf.set_font("Arial", "", 9)
    pdf.cell(0, 6, data_conclusao.strftime("%Y"), ln=1, align="C")

    pdf_output = pdf.output(dest="S").encode("latin-1")
    buffer = BytesIO(pdf_output)
    buffer.seek(0)
    return buffer


def _generate_payment_whatsapp_text(
    client_name: str,
    budget_id: int,
    valor_final: float,
    data_pagamento: datetime,
) -> str:
    """Mensagem curta para confirmar pagamento via WhatsApp."""
    linhas = [
        f"Olá {client_name}, tudo bem?",
        f"Confirmamos o pagamento do orçamento #{budget_id}.",
        f"Valor recebido: R$ {valor_final:.2f}",
        f"Data: {data_pagamento.strftime('%d/%m/%Y')}",
        "",
        "Obrigado pela preferência! Qualquer dúvida é só chamar.",
    ]
    return "\n".join(linhas)


def _generate_service_payment_whatsapp_text(
    client_name: str,
    service_ref,
    valor_final: float,
    data_pagamento: datetime,
) -> str:
    """Mensagem curta para confirmar pagamento de serviço via WhatsApp."""
    linhas = [
        f"Olá {client_name}, tudo bem?",
        f"Confirmamos o pagamento da OS {service_ref}.",
        f"Valor recebido: R$ {valor_final:.2f}",
        f"Data: {data_pagamento.strftime('%d/%m/%Y')}",
        "",
        "Obrigado pela preferência! Qualquer dúvida é só chamar.",
    ]
    return "\n".join(linhas)


def _generate_service_receipt_pdf(
    service_id: int,
    service: dict,
    client: dict,
    items: list,
    valor_final: float,
    data_conclusao: datetime,
    receipt_number=None,
) -> BytesIO:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"RECIBO N\u00ba: {receipt_number or service_id}", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 6, COMPANY_INFO.get("razao_social", ""), ln=1)
    pdf.cell(0, 6, COMPANY_INFO.get("endereco", ""), ln=1)
    pdf.cell(0, 6, COMPANY_INFO.get("telefone", ""), ln=1)
    if COMPANY_INFO.get("email"):
        pdf.cell(0, 6, COMPANY_INFO.get("email"), ln=1)
    pdf.ln(6)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "CLIENTE", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 6, client.get("nome", ""), ln=1)
    pdf.cell(0, 6, f"Telefone: {client.get('telefone_whatsapp', '')}", ln=1)
    pdf.ln(4)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "SERVIÇO", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 6, service.get("descricao_servico", ""), border=0)
    pdf.ln(4)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "ITENS", ln=1)
    pdf.set_font("Arial", "", 10)
    for item in items:
        descricao = item.get("descricao", "")
        quantidade = item.get("quantidade", 1)
        valor_unitario = float(item.get("valor_unitario", 0) or 0)
        subtotal = float(item.get("subtotal", 0) or 0)
        pdf.multi_cell(0, 6, f"- {descricao} ({quantidade}x R$ {valor_unitario:.2f}) = R$ {subtotal:.2f}")

    pdf.ln(4)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "VALOR TOTAL", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 6, f"R$ {valor_final:.2f}", ln=1)
    pdf.ln(4)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "DADOS", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 6, f"Data: {data_conclusao.strftime('%d/%m/%Y')}", ln=1)
    pdf.cell(0, 6, f"Responsável: {service.get('responsavel', '')}", ln=1)
    pdf.ln(8)

    pdf.set_font("Arial", "I", 9)
    pdf.multi_cell(
        0,
        5,
        "Este recibo comprova o pagamento do serviço informado. Qualquer dúvida, entre em contato com a oficina.",
    )

    buffer = BytesIO(pdf.output(dest="S").encode("latin-1", errors="replace"))
    buffer.seek(0)
    return buffer


def _load_vehicles_by_client(clients: list) -> dict:
    """Monta dict {str(id_cliente): [veiculos]} incluindo fallback de campos legados."""
    vmap = _build_vehicles_map()
    result: dict = {}
    for c in clients:
        cid = c["id_cliente"]
        veiculos = vmap.get(cid, [])
        if not veiculos and (c.get("carro_marca") or c.get("carro_placa")):
            veiculos = [{"id_veiculo": None, "id_cliente": cid,
                         "marca": c.get("carro_marca", ""), "modelo": c.get("carro_modelo", ""),
                         "ano": c.get("carro_ano", ""), "placa": c.get("carro_placa", "")}]
        result[str(cid)] = veiculos
    return result


@app.route("/orcamentos/novo", methods=["GET", "POST"])
def novo_orcamento():
    clients_df = dal.get_all_clients().fillna("")
    clients = clients_df.to_dict(orient="records")
    employees = _get_active_employees()
    vehicles_by_client = _load_vehicles_by_client(clients)

    if request.method == "POST":
        try:
            client_id = int(request.form.get("id_cliente", ""))
        except (TypeError, ValueError):
            flash("Selecione um cliente válido.", "danger")
            return redirect(url_for("novo_orcamento"))
        client = dal.get_client_by_id(client_id)
        if not client:
            flash("Cliente informado não existe.", "danger")
            return redirect(url_for("novo_orcamento"))

        id_veiculo_raw = request.form.get("id_veiculo", "").strip()
        id_veiculo = None
        if id_veiculo_raw and id_veiculo_raw.lower() not in ("", "none", "null"):
            try:
                id_veiculo = int(id_veiculo_raw)
            except (TypeError, ValueError):
                pass

        payment_method = request.form.get("forma_pagamento", "PIX")
        if payment_method not in PAYMENT_OPTIONS:
            payment_method = "PIX"

        responsavel_raw = request.form.get("responsavel_execucao", "").strip()
        responsavel_id = None
        responsavel_nome = ""
        try:
            responsavel_id = int(responsavel_raw) if responsavel_raw else None
        except (TypeError, ValueError):
            responsavel_id = None
        if responsavel_id:
            emp = dal.get_employee_by_id(responsavel_id)
            if emp:
                responsavel_nome = emp.get("nome", "")

        carro_km  = request.form.get("carro_km",  "").strip()
        carro_cor = request.form.get("carro_cor", "").strip()

        items = _build_budget_items_from_form(request.form)
        if not items:
            flash("Adicione pelo menos um item ao orçamento.", "warning")
            return redirect(url_for("novo_orcamento"))

        base_total = sum(item["subtotal"] for item in items)
        total, taxa = _calculate_total_with_payment(base_total, payment_method)
        texto_whatsapp = _generate_whatsapp_text(
            client["nome"], items, total, payment_method, taxa
        )
        whatsapp_url = _build_whatsapp_url(client.get("telefone_whatsapp", ""), texto_whatsapp)

        data = {
            "id_cliente":                client_id,
            "id_veiculo":                id_veiculo,
            "data_criacao":              datetime.today().strftime("%Y-%m-%d"),
            "status":                    BUDGET_STATUS_PENDING_ADMIN,
            "carro_km":                  carro_km,
            "carro_cor":                 carro_cor,
            "responsavel_planejado_id":  responsavel_id or "",
            "responsavel_planejado_nome": responsavel_nome,
            "itens":                     json.dumps(items, ensure_ascii=False),
            "valor_total":               total,
            "texto_whatsapp":            texto_whatsapp,
            "data_aprovacao":            "",
            "data_conclusao":            "",
            "forma_pagamento":           payment_method,
        }
        new_id = dal.add_budget(data)
        flash("Orçamento enviado para validação administrativa.", "success")
        return render_template(
            "orcamento_criado.html",
            orcamento_id=new_id,
            client=client,
            items=items,
            base_total=base_total,
            total=total,
            taxa=taxa,
            forma_pagamento=payment_method,
            texto_whatsapp=texto_whatsapp,
            whatsapp_url=whatsapp_url,
            pending_admin=True,
        )

    return render_template(
        "novo_orcamento.html",
        clients=clients,
        payment_options=PAYMENT_OPTIONS,
        employees=employees,
        vehicles_by_client=vehicles_by_client,
    )


@app.route("/orcamentos")
def listar_orcamentos():
    _sync_completed_budget_financial_entries_safely()
    filtro = request.args.get("filtro", "").strip().lower()
    budgets_df = dal.get_all_budgets()
    clients_df = dal.get_all_clients()[["id_cliente", "nome"]]
    merged = budgets_df.merge(clients_df, left_on="id_cliente", right_on="id_cliente", how="left")
    if filtro == "abertos" and not merged.empty:
        status_norm = merged["status"].fillna("").astype(str).apply(_normalize_status)
        merged = merged[(~status_norm.isin(FINALIZED_BUDGET_STATUSES)) & (status_norm != "reprovado")]
    merged = merged.sort_values("data_criacao", ascending=False)
    orcamentos = merged.to_dict(orient="records")
    is_admin = session.get("role") == ROLE_ADMIN
    for orcamento in orcamentos:
        status = orcamento.get("status") or ""
        is_finalizado = _is_budget_finalized(status)
        is_admin_approved = _is_budget_admin_approved(status)
        is_pending_admin = _is_budget_pending_admin(status)
        orcamento["is_finalizado"] = is_finalizado
        orcamento["is_pending_admin"] = is_pending_admin
        orcamento["can_admin_approve"] = is_admin and is_pending_admin
        orcamento["can_efetivar"] = is_admin and is_admin_approved and not is_finalizado
        orcamento["can_editar"] = is_admin and not is_finalizado
        orcamento["can_reprovar"] = is_admin and not is_finalizado
    return render_template("listar_orcamentos.html", orcamentos=orcamentos, filtro=filtro)


@app.route("/orcamentos/<int:budget_id>")
def detalhes_orcamento(budget_id: int):
    budget = dal.get_budget_by_id(budget_id)
    if not budget:
        flash("Orçamento não encontrado.", "danger")
        return redirect(url_for("listar_orcamentos"))

    client = dal.get_client_by_id(int(budget["id_cliente"]))
    veiculo = _get_veiculo_for_orcamento(budget, client or {})
    items = dal.parse_budget_items(budget["itens"])
    base_total = sum(float(item.get("subtotal", item.get("quantidade", 0) * item.get("valor_unitario", 0)) or 0) for item in items)
    forma_pagamento = budget.get("forma_pagamento") or "PIX"
    if forma_pagamento not in PAYMENT_OPTIONS:
        forma_pagamento = "PIX"
    final_total = float(budget.get("valor_total", base_total) or base_total)
    taxa = max(0.0, round(final_total - base_total, 2))
    status = budget.get("status")
    is_admin = session.get("role") == ROLE_ADMIN
    is_finalizado = _is_budget_finalized(status)
    is_admin_approved = _is_budget_admin_approved(status)
    is_pending_admin = _is_budget_pending_admin(status)
    budget_order_number = _service_order_from_records(_get_budget_service_records(budget_id))

    return render_template(
        "detalhes_orcamento.html",
        budget=budget,
        client=client,
        veiculo=veiculo,
        items=items,
        base_total=base_total,
        final_total=final_total,
        taxa=taxa,
        forma_pagamento=forma_pagamento,
        is_pending_admin=is_pending_admin,
        is_admin_approved=is_admin_approved,
        can_admin_approve=is_admin and is_pending_admin,
        can_efetivar=is_admin and is_admin_approved and not is_finalizado,
        can_edit=is_admin and not is_finalizado,
        can_reprovar=is_admin and not is_finalizado,
        can_send_to_client=is_admin_approved,
        can_download_pdf=is_admin_approved,
        can_recibo=is_finalizado,
        budget_order_number=budget_order_number,
    )


@app.route("/orcamentos/<int:budget_id>/editar", methods=["GET", "POST"])
@require_admin
def editar_orcamento(budget_id: int):
    budget = dal.get_budget_by_id(budget_id)
    if not budget:
        flash("Orçamento não encontrado.", "danger")
        return redirect(url_for("listar_orcamentos"))

    clients_df = dal.get_all_clients().fillna("")
    clients = clients_df.to_dict(orient="records")
    items = dal.parse_budget_items(budget["itens"])
    base_total = sum(
        float(
            item.get(
                "subtotal",
                item.get("quantidade", 0) * item.get("valor_unitario", 0),
            )
            or 0
        )
        for item in items
    )
    current_payment = budget.get("forma_pagamento") or "PIX"
    if current_payment not in PAYMENT_OPTIONS:
        current_payment = "PIX"
    final_total = float(budget.get("valor_total", base_total) or base_total)
    employees = _get_active_employees()
    vehicles_by_client = _load_vehicles_by_client(clients)

    if request.method == "POST":
        try:
            client_id = int(request.form.get("id_cliente", ""))
        except (TypeError, ValueError):
            flash("Selecione um cliente válido.", "danger")
            return redirect(url_for("editar_orcamento", budget_id=budget_id))
        client = dal.get_client_by_id(client_id)
        if not client:
            flash("Cliente selecionado não existe.", "danger")
            return redirect(url_for("editar_orcamento", budget_id=budget_id))

        id_veiculo_raw = request.form.get("id_veiculo", "").strip()
        id_veiculo = None
        if id_veiculo_raw and id_veiculo_raw.lower() not in ("", "none", "null"):
            try:
                id_veiculo = int(id_veiculo_raw)
            except (TypeError, ValueError):
                pass

        payment_method = request.form.get("forma_pagamento", current_payment)
        if payment_method not in PAYMENT_OPTIONS:
            payment_method = "PIX"

        carro_km  = request.form.get("carro_km",  "").strip()
        carro_cor = request.form.get("carro_cor", "").strip()
        responsavel_raw = request.form.get("responsavel_execucao", "").strip()
        responsavel_id = None
        responsavel_nome = ""
        try:
            responsavel_id = int(responsavel_raw) if responsavel_raw else None
        except (TypeError, ValueError):
            responsavel_id = None
        if responsavel_id:
            emp = dal.get_employee_by_id(responsavel_id)
            if emp:
                responsavel_nome = emp.get("nome", "")

        updated_items = _build_budget_items_from_form(request.form)
        if not updated_items:
            flash("Inclua ao menos um item no orçamento.", "warning")
            return redirect(url_for("editar_orcamento", budget_id=budget_id))

        base_total = sum(item["subtotal"] for item in updated_items)
        total, taxa = _calculate_total_with_payment(base_total, payment_method)
        texto_whatsapp = _generate_whatsapp_text(
            client["nome"], updated_items, total, payment_method, taxa
        )

        dal.update_budget(
            budget_id,
            {
                "id_cliente":                client_id,
                "id_veiculo":                id_veiculo,
                "carro_km":                  carro_km,
                "carro_cor":                 carro_cor,
                "responsavel_planejado_id":  responsavel_id or "",
                "responsavel_planejado_nome": responsavel_nome,
                "itens":                     json.dumps(updated_items, ensure_ascii=False),
                "valor_total":               total,
                "texto_whatsapp":            texto_whatsapp,
                "forma_pagamento":           payment_method,
            },
        )

        flash("Orçamento atualizado com sucesso!", "success")
        return redirect(url_for("detalhes_orcamento", budget_id=budget_id))

    return render_template(
        "editar_orcamento.html",
        budget=budget,
        clients=clients,
        items=items,
        payment_options=PAYMENT_OPTIONS,
        current_payment=current_payment,
        base_total=base_total,
        final_total=final_total,
        employees=employees,
        vehicles_by_client=vehicles_by_client,
        responsavel_planejado_id=budget.get("responsavel_planejado_id"),
        responsavel_planejado_nome=budget.get("responsavel_planejado_nome"),
    )


@app.route("/orcamentos/<int:budget_id>/pdf")
def gerar_pdf_orcamento(budget_id: int):
    budget = dal.get_budget_by_id(budget_id)
    if not budget:
        flash("Orçamento não encontrado.", "danger")
        return redirect(url_for("listar_orcamentos"))
    if not _is_budget_admin_approved(budget.get("status")):
        flash("Valide o orçamento como administrador antes de gerar PDF para o cliente.", "warning")
        return redirect(url_for("detalhes_orcamento", budget_id=budget_id))

    client = dal.get_client_by_id(int(budget["id_cliente"]))
    if not client:
        flash("Cliente associado ao orçamento não foi localizado.", "warning")
        return redirect(url_for("listar_orcamentos"))

    items = dal.parse_budget_items(budget["itens"])
    veiculo = _get_veiculo_for_orcamento(budget, client)
    pdf_buffer = _generate_budget_pdf(budget, client, items, veiculo=veiculo)
    filename = f"orcamento_{budget_id}.pdf"
    pdf_buffer.seek(0)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


@app.route("/orcamentos/<int:budget_id>/recibo")
def gerar_recibo(budget_id: int):
    budget = dal.get_budget_by_id(budget_id)
    if not budget:
        flash("Orçamento não encontrado.", "danger")
        return redirect(url_for("listar_orcamentos"))
    if not _is_budget_finalized(budget.get("status", "")):
        flash("O recibo só está disponível para orçamentos concluídos.", "warning")
        return redirect(url_for("detalhes_orcamento", budget_id=budget_id))

    client = dal.get_client_by_id(int(budget["id_cliente"]))
    if not client:
        flash("Cliente associado ao orçamento não foi localizado.", "warning")
        return redirect(url_for("listar_orcamentos"))

    items = dal.parse_budget_items(budget.get("itens", ""))
    base_total = sum(
        float(item.get("subtotal", item.get("quantidade", 0) * item.get("valor_unitario", 0)) or 0)
        for item in items
    )
    valor_final = float(budget.get("valor_total", base_total) or base_total)
    data_conclusao = pd.to_datetime(
        budget.get("data_conclusao") or budget.get("data_criacao") or datetime.today()
    )

    responsavel_receipt = ""
    services_df = dal.get_all_services()
    if "responsavel" in services_df.columns:
        resp_candidates = services_df[
            (services_df["id_orcamento"] == budget_id) & services_df["responsavel"].notna()
        ]
        if not resp_candidates.empty:
            responsavel_receipt = str(resp_candidates.iloc[0]["responsavel"]).strip()
    if not responsavel_receipt:
        responsavel_receipt = budget.get("responsavel_planejado_nome", "")

    veiculo = _get_veiculo_for_orcamento(budget, client)
    pdf_buffer = _generate_receipt_pdf(
        budget_id=budget_id,
        budget=budget,
        client=client,
        items=items,
        valor_final=valor_final,
        data_conclusao=data_conclusao,
        responsavel_execucao=responsavel_receipt,
        veiculo=veiculo,
    )
    filename = f"recibo_{budget_id}_{_slugify_filename(client.get('nome', ''))}.pdf"
    pdf_buffer.seek(0)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


@app.route("/servicos/<int:service_id>/recibo")
def gerar_recibo_servico(service_id: int):
    service = dal.get_service_by_id(service_id)
    if not service:
        flash("Serviço não encontrado.", "danger")
        return redirect(url_for("historico_servicos"))
    services_group = _get_service_group(service)
    primary_service = services_group[0] if services_group else service
    service_ref = _service_order_label(primary_service)
    if any(str(s.get("status") or "").lower() != "concluído" for s in services_group):
        flash("O recibo só está disponível para serviços concluídos.", "warning")
        return redirect(url_for("historico_servicos"))

    client = dal.get_client_by_id(int(primary_service.get("id_cliente"))) if primary_service.get("id_cliente") else None
    if not client:
        flash("Cliente associado ao serviço não foi localizado.", "warning")
        return redirect(url_for("historico_servicos"))

    items = _build_service_items_from_services(services_group)
    valor_final = sum(float(item.get("subtotal") or 0) for item in items)
    produto_descricao = primary_service.get("produto_descricao")
    produto_valor = float(primary_service.get("produto_valor") or 0)
    if produto_descricao and produto_valor > 0:
        items.append({
            "descricao": produto_descricao,
            "quantidade": 1,
            "valor_unitario": produto_valor,
            "subtotal": produto_valor,
        })
        valor_final += produto_valor

    data_conclusao = _parse_date(primary_service.get("data_execucao")) or datetime.today()
    service_context = dict(primary_service)
    if primary_service.get("ordem_servico"):
        service_context["descricao_servico"] = f"Ordem de serviço {service_ref}"
    pdf_buffer = _generate_service_receipt_pdf(
        service_id=service_id,
        service=service_context,
        client=client,
        items=items,
        valor_final=valor_final,
        data_conclusao=data_conclusao,
        receipt_number=service_ref,
    )
    filename = f"recibo_{_slugify_filename(service_ref)}_{_slugify_filename(client.get('nome', ''))}.pdf"
    pdf_buffer.seek(0)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


@app.route("/orcamentos/<int:budget_id>/aprovar-admin", methods=["POST"])
@require_admin
def aprovar_orcamento_admin(budget_id: int):
    budget = dal.get_budget_by_id(budget_id)
    if not budget:
        flash("Orçamento não encontrado.", "danger")
        return redirect(url_for("listar_orcamentos"))
    if _is_budget_finalized(budget.get("status")):
        flash("Orçamento concluído não pode voltar para validação administrativa.", "info")
        return redirect(url_for("detalhes_orcamento", budget_id=budget_id))
    if _normalize_status(budget.get("status")) == "reprovado":
        flash("Orçamento reprovado não pode ser aprovado sem reabertura.", "warning")
        return redirect(url_for("detalhes_orcamento", budget_id=budget_id))

    dal.update_budget(budget_id, {"status": BUDGET_STATUS_ADMIN_APPROVED})
    flash("Orçamento aprovado pelo admin. Agora ele pode ser enviado ao cliente.", "success")
    return redirect(url_for("detalhes_orcamento", budget_id=budget_id))


@app.route("/orcamentos/<int:budget_id>/reprovar", methods=["POST"])
@require_admin
def reprovar_orcamento(budget_id: int):
    budget = dal.get_budget_by_id(budget_id)
    if not budget:
        flash("Orçamento não encontrado.", "danger")
        return redirect(url_for("listar_orcamentos"))

    dal.update_budget(
        budget_id,
        {
            "status": "Reprovado",
            "data_conclusao": datetime.today().strftime("%Y-%m-%d"),
        },
    )
    flash("Orçamento marcado como reprovado.", "info")
    return redirect(url_for("listar_orcamentos"))


@app.route("/orcamentos/<int:budget_id>/efetivar", methods=["GET", "POST"])
@require_admin
def efetivar_orcamento(budget_id: int):
    budget = dal.get_budget_by_id(budget_id)
    if not budget:
        flash("Orçamento não encontrado.", "danger")
        return redirect(url_for("listar_orcamentos"))
    if _is_budget_finalized(budget.get("status")):
        flash("Este orçamento já foi concluído e não pode ser efetivado novamente.", "info")
        return redirect(url_for("listar_orcamentos"))
    if not _is_budget_admin_approved(budget.get("status")):
        flash("O orçamento precisa da validação administrativa antes de ser efetivado.", "warning")
        return redirect(url_for("detalhes_orcamento", budget_id=budget_id))

    client = dal.get_client_by_id(int(budget["id_cliente"]))
    items = dal.parse_budget_items(budget["itens"])
    base_total = sum(
        float(item.get("subtotal", item.get("quantidade", 0) * item.get("valor_unitario", 0)) or 0)
        for item in items
    )
    employees = _get_active_employees()

    if request.method == "POST":
        forma_pagamento = request.form.get("forma_pagamento", "")
        data_status = _parse_date(request.form.get("data_conclusao"))
        status_final = request.form.get("status_final", "Concluído")
        is_final_approval = _is_budget_finalized(status_final)
        responsavel_id_raw = request.form.get("responsavel_execucao", "").strip()
        responsavel_execucao = ""
        if forma_pagamento not in PAYMENT_OPTIONS:
            flash("Escolha uma forma de pagamento válida.", "warning")
            return redirect(url_for("efetivar_orcamento", budget_id=budget_id))
        if is_final_approval:
            try:
                responsavel_id = int(responsavel_id_raw)
            except (TypeError, ValueError):
                responsavel_id = None
            employee = dal.get_employee_by_id(responsavel_id) if responsavel_id else None
            if not employee:
                flash("Informe quem executou o serviço.", "warning")
                return redirect(url_for("efetivar_orcamento", budget_id=budget_id))
            responsavel_execucao = str(employee.get("nome", "")).strip()
        if is_final_approval and not responsavel_execucao:
            flash("Informe quem executou o serviço.", "warning")
            return redirect(url_for("efetivar_orcamento", budget_id=budget_id))

        taxa = 0.0
        valor_final = base_total
        if forma_pagamento == "Cartão Crédito":
            taxa = round(base_total * TAXA_CARTAO_CREDITO, 2)
            valor_final = round(base_total + taxa, 2)

        data_conclusao_str = data_status.strftime("%Y-%m-%d") if is_final_approval else ""
        dal.update_budget(
            budget_id,
            {
                "status": status_final,
                "data_aprovacao": data_status.strftime("%Y-%m-%d"),
                "data_conclusao": data_conclusao_str,
                "forma_pagamento": forma_pagamento,
                "valor_total": valor_final,
            },
        )

        service_status = "Concluído" if is_final_approval else "Aprovado"
        service_responsavel = responsavel_execucao if is_final_approval else str(
            budget.get("responsavel_planejado_nome") or ""
        ).strip()
        service_sync = _sync_budget_services_from_items(
            budget_id,
            budget,
            items,
            data_execucao=data_status,
            status=service_status,
            responsavel=service_responsavel,
        )
        ordem_servico = service_sync["ordem_servico"]

        if not is_final_approval:
            flash(
                f"Orçamento aprovado para execução. OS {ordem_servico} gerada. Nenhum lançamento financeiro foi criado até a conclusão.",
                "info",
            )
            return redirect(url_for("detalhes_orcamento", budget_id=budget_id))

        existing_financial_df = dal.get_all_financial_entries()
        budget_has_financial_entry = False
        if not existing_financial_df.empty:
            normalized_types = existing_financial_df["tipo_lancamento"].fillna("").astype(str).apply(_normalize_status)
            related_budget = pd.to_numeric(
                existing_financial_df.get("relacionado_orcamento_id"), errors="coerce"
            )
            budget_has_financial_entry = ((normalized_types == "entrada") & (related_budget == budget_id)).any()

        if not budget_has_financial_entry:
            dal.add_financial_entry(
                {
                    "data": data_status.strftime("%Y-%m-%d"),
                    "tipo_lancamento": "Entrada",
                    "categoria": FINANCIAL_ENTRY_CATEGORY_BUDGET,
                    "descricao": f"Orçamento #{budget_id} - {client['nome']}",
                    "valor": valor_final,
                    "relacionado_orcamento_id": budget_id,
                    "relacionado_servico_id": None,
                }
            )
        else:
            app.logger.warning("Lançamento financeiro já existente para orçamento %s; inserção duplicada evitada.", budget_id)

        # Lança custo de peças (Saída) automaticamente para itens do tipo Produto com custo informado
        custo_total_pecas = sum(
            item.get("custo_total", 0.0)
            for item in items
            if item.get("tipo") == "Produto" and item.get("custo_total", 0.0) > 0
        )
        if custo_total_pecas > 0:
            budget_has_cost_entry = False
            if not existing_financial_df.empty:
                normalized_types = existing_financial_df["tipo_lancamento"].fillna("").astype(str).apply(_normalize_status)
                related_budget = pd.to_numeric(existing_financial_df.get("relacionado_orcamento_id"), errors="coerce")
                desc_col = existing_financial_df["descricao"].fillna("").astype(str)
                budget_has_cost_entry = (
                    (normalized_types == "saida") &
                    (related_budget == budget_id) &
                    desc_col.str.startswith("Custo de peças")
                ).any()
            if not budget_has_cost_entry:
                dal.add_financial_entry(
                    {
                        "data": data_status.strftime("%Y-%m-%d"),
                        "tipo_lancamento": "Saída",
                        "categoria": "Materiais e peças - Componentes automotivos",
                        "descricao": f"Custo de peças - Orçamento #{budget_id}",
                        "valor": round(custo_total_pecas, 2),
                        "relacionado_orcamento_id": budget_id,
                        "relacionado_servico_id": None,
                    }
                )

        pagamento_texto_whatsapp = _generate_payment_whatsapp_text(
            client.get("nome", "cliente"), budget_id, valor_final, data_status
        )

        return render_template(
            "pagamento_concluido.html",
            budget_id=budget_id,
            client=client,
            items=items,
            valor_final=valor_final,
            data_pagamento=data_status,
            texto_whatsapp=pagamento_texto_whatsapp,
            service_order=ordem_servico,
        )

    return render_template(
        "efetivar_orcamento.html",
        budget=budget,
        client=client,
        items=items,
        payment_options=PAYMENT_OPTIONS,
        base_total=base_total,
        employees=employees,
        today_str=datetime.today().strftime("%Y-%m-%d"),
        taxa_cartao=TAXA_CARTAO_CREDITO,
    )


@app.route("/financeiro", methods=["GET", "POST"])
@require_admin
def financeiro():
    if request.method == "POST":
        payload, error = _build_expense_payload_from_form(request.form)
        if error:
            flash(error, "danger")
            return redirect(url_for("financeiro"))

        try:
            dal.add_financial_entry(payload)
        except Exception:
            app.logger.exception("Erro ao salvar despesa no financeiro.")
            flash("Não foi possível salvar a despesa. Verifique as configurações do banco e tente novamente.", "danger")
            return redirect(url_for("financeiro"))

        flash("Despesa registrada com sucesso.", "success")
        return redirect(url_for("financeiro"))

    _sync_completed_budget_financial_entries_safely()
    data_inicio = request.args.get("data_inicio")
    data_fim = request.args.get("data_fim")
    tipo = request.args.get("tipo")

    # Lista de orçamentos para o campo "Orçamento relacionado" no formulário de despesa
    budgets_df = dal.get_all_budgets()
    clients_df = dal.get_all_clients().fillna("")
    client_name_map = {
        int(r["id_cliente"]): r["nome"]
        for r in clients_df.to_dict(orient="records")
        if r.get("id_cliente")
    }
    budget_options = []
    if not budgets_df.empty:
        for b in budgets_df.sort_values("id_orcamento", ascending=False).to_dict(orient="records"):
            bid = _coerce_int(b.get("id_orcamento"))
            if not bid:
                continue
            cname = client_name_map.get(_coerce_int(b.get("id_cliente")), "")
            budget_options.append({
                "id": bid,
                "label": f"#{bid} — {cname} ({b.get('status', '')})",
            })

    entries_df = dal.get_all_financial_entries()
    entries_df["data"] = pd.to_datetime(entries_df["data"], errors="coerce")

    if data_inicio:
        entries_df = entries_df[entries_df["data"] >= _parse_date(data_inicio)]
    if data_fim:
        entries_df = entries_df[entries_df["data"] <= _parse_date(data_fim)]
    if tipo in {"Entrada", "Saída"}:
        tipo_norm = _normalize_status(tipo)
        entries_df = entries_df[
            entries_df["tipo_lancamento"].fillna("").astype(str).apply(_normalize_status) == tipo_norm
        ]

    entries_df = entries_df.sort_values("data", ascending=False)
    tipo_norm_entrada = _normalize_status("Entrada")
    tipo_norm_saida = _normalize_status("Saída")
    tipo_series = entries_df["tipo_lancamento"].fillna("").astype(str).apply(_normalize_status)
    total_entradas = entries_df[tipo_series == tipo_norm_entrada]["valor"].sum()
    total_saidas = entries_df[tipo_series == tipo_norm_saida]["valor"].sum()

    entries = []
    for entry in entries_df.to_dict(orient="records"):
        entry["data_formatada"] = _format_date(entry["data"])
        entry["is_expense"] = _is_expense_entry(entry)
        entries.append(entry)

    return render_template(
        "financeiro.html",
        entries=entries,
        total_entradas=total_entradas,
        total_saidas=total_saidas,
        saldo=total_entradas - total_saidas,
        data_inicio=data_inicio,
        data_fim=data_fim,
        tipo=tipo,
        expense_types=FINANCE_EXPENSE_TYPES,
        today_str=datetime.today().strftime("%Y-%m-%d"),
        budget_options=budget_options,
    )


@app.route("/financeiro/<int:entry_id>/editar", methods=["GET", "POST"])
@require_admin
def editar_despesa_financeira(entry_id: int):
    entry = dal.get_financial_entry_by_id(entry_id)
    if not entry:
        flash("Lançamento financeiro não encontrado.", "danger")
        return redirect(url_for("financeiro"))
    if not _is_expense_entry(entry):
        flash("Apenas despesas podem ser editadas por esta tela.", "warning")
        return redirect(url_for("financeiro"))

    if request.method == "POST":
        payload, error = _build_expense_payload_from_form(request.form)
        if error:
            flash(error, "danger")
            return redirect(url_for("editar_despesa_financeira", entry_id=entry_id))

        dal.update_financial_entry(entry_id, payload)
        flash("Despesa atualizada com sucesso.", "success")
        return redirect(url_for("financeiro"))

    tipo_despesa, categoria = _split_expense_category(entry.get("categoria", ""))

    budgets_df = dal.get_all_budgets()
    clients_df = dal.get_all_clients().fillna("")
    client_name_map = {
        int(r["id_cliente"]): r["nome"]
        for r in clients_df.to_dict(orient="records")
        if r.get("id_cliente")
    }
    budget_options = []
    if not budgets_df.empty:
        for b in budgets_df.sort_values("id_orcamento", ascending=False).to_dict(orient="records"):
            bid = _coerce_int(b.get("id_orcamento"))
            if not bid:
                continue
            cname = client_name_map.get(_coerce_int(b.get("id_cliente")), "")
            budget_options.append({
                "id": bid,
                "label": f"#{bid} — {cname} ({b.get('status', '')})",
            })

    return render_template(
        "editar_despesa.html",
        entry=entry,
        expense_types=FINANCE_EXPENSE_TYPES,
        selected_type=tipo_despesa,
        selected_category=categoria,
        budget_options=budget_options,
    )


@app.route("/financeiro/<int:entry_id>/excluir", methods=["POST"])
@require_admin
def excluir_despesa_financeira(entry_id: int):
    entry = dal.get_financial_entry_by_id(entry_id)
    if not entry:
        flash("Lançamento financeiro não encontrado.", "danger")
        return redirect(url_for("financeiro"))
    if not _is_expense_entry(entry):
        flash("Apenas despesas podem ser excluídas por esta tela.", "warning")
        return redirect(url_for("financeiro"))

    dal.delete_financial_entry(entry_id)
    flash("Despesa excluída com sucesso.", "success")
    return redirect(url_for("financeiro"))


@app.route("/ajuda")
def ajuda():
    return render_template("ajuda.html")


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"

    def open_browser():
        webbrowser.open_new("http://127.0.0.1:5000/")

    if not os.environ.get("FLASK_NO_BROWSER") and not os.environ.get("WERKZEUG_RUN_MAIN"):
        Timer(1, open_browser).start()

    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug_mode, use_reloader=debug_mode)
