"""
Gera um script SQL para corrigir lints de seguranca do Supabase.

Uso:
    python exportar_seguranca_supabase.py \
      --csv "c:\\caminho\\Supabase Performance Security Lints (...).csv" \
      --out supabase_security_hardening.sql
"""
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


def _extract_tables(csv_path: Path) -> list[str]:
    tables: list[str] = []
    seen: set[str] = set()

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if row.get("name") != "rls_disabled_in_public":
                continue

            detail = (row.get("detail") or "").strip()
            # Aceita tanto `public.tabela` quanto \`public.tabela\` no CSV exportado.
            match = re.search(r"public\.([A-Za-z0-9_]+)", detail)
            if not match:
                continue
            table_name = match.group(1).strip()
            if table_name and table_name not in seen:
                tables.append(table_name)
                seen.add(table_name)

    return tables


def _build_sql(tables: list[str]) -> str:
    lines = [
        "-- Correcoes de seguranca para lints do Supabase (RLS Disabled in Public)",
        "-- Execute no SQL Editor do Supabase.",
        "",
        "BEGIN;",
        "",
    ]
    for table in tables:
        lines.append(f"ALTER TABLE IF EXISTS public.{table} ENABLE ROW LEVEL SECURITY;")
    lines.extend(["", "COMMIT;", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Exporta SQL de hardening RLS a partir do CSV do Supabase.")
    parser.add_argument("--csv", required=True, help="Caminho do CSV exportado pelo Supabase.")
    parser.add_argument("--out", default="supabase_security_hardening.sql", help="Arquivo SQL de saida.")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV nao encontrado: {csv_path}")

    tables = _extract_tables(csv_path)
    if not tables:
        raise RuntimeError("Nenhuma tabela com lint rls_disabled_in_public foi encontrada no CSV.")

    sql = _build_sql(tables)
    out_path = Path(args.out)
    out_path.write_text(sql, encoding="utf-8")
    print(f"SQL exportado com sucesso: {out_path.resolve()}")
    print("Tabelas:")
    for table in tables:
        print(f"- public.{table}")


if __name__ == "__main__":
    main()
