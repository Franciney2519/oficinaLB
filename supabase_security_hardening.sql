-- Correcoes de seguranca para lints do Supabase (RLS Disabled in Public)
-- Execute no SQL Editor do Supabase.

BEGIN;

ALTER TABLE IF EXISTS public.clientes ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.orcamentos ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.servicos ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.funcionarios ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.financeiro ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.veiculos ENABLE ROW LEVEL SECURITY;

COMMIT;
