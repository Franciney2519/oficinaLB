# Manual de Uso — LB AUTOCAR

Sistema web de gestão de oficina mecânica. Acesse pelo navegador com o endereço fornecido pelo administrador.

---

## 1. Login

Na tela inicial informe o **usuário** e **senha** fornecidos pelo administrador e clique em **Entrar**.

---

## 2. Dashboard

Tela inicial após o login. Mostra um resumo do período selecionado.

- **Filtro de período**: escolha o mês e ano e clique em **Aplicar**. Clique em **Limpar** para voltar ao mês atual.
- **Cartões de resumo**:
  - *Clientes cadastrados* — total de clientes no sistema.
  - *Orçamentos em aberto* — orçamentos que ainda não foram concluídos ou reprovados.
  - *Saldo do período* — entradas menos saídas do mês selecionado.
- **Gráfico financeiro**: barras de entradas e saídas dos últimos 12 meses com linha de saldo.
- **Desempenho por executor**: lista os funcionários com o valor total de serviços concluídos no período.
- **Ações rápidas**: botões para ir direto a Clientes, Novo orçamento, Orçamentos e Financeiro.

---

## 3. Clientes

### 3.1 Lista de clientes

Mostra todos os clientes cadastrados com nome, WhatsApp e os veículos vinculados.

- **Editar**: abre o formulário de edição do cliente.
- **Histórico**: exibe todos os serviços executados para aquele cliente.

### 3.2 Cadastrar novo cliente

Preencha os dados pessoais (nome, telefone, e-mail, endereço).

**Veículos**: na seção *Veículos*, preencha os campos do primeiro carro (marca, modelo, ano, placa, cor). Para adicionar mais de um veículo de uma só vez, clique em **+ Adicionar outro veículo**. Clique no **×** para remover uma linha.

> É possível cadastrar o cliente sem veículo e adicionar os carros depois pela tela de edição.

Clique em **Cadastrar** para salvar.

### 3.3 Editar cliente

Divida em duas partes:

**Dados pessoais**: altere os campos e clique em **Salvar alterações**.

**Veículos**:
- Cada veículo aparece listado com marca, modelo, ano, placa e cor.
- Clique em **Editar** para expandir o formulário inline e alterar os dados. Clique em **Salvar veículo** para confirmar.
- Clique em **Remover** para excluir o veículo (confirme na janela de confirmação).
- Para adicionar um novo veículo, preencha o formulário na parte inferior e clique em **Adicionar veículo**.

---

## 4. Orçamentos

### 4.1 Listar orçamentos

Mostra todos os orçamentos com status, cliente e data. Os botões de ação variam conforme o status:

| Status | Ações disponíveis |
|---|---|
| Em análise | Editar, Efetivar, Baixar PDF, Reprovar |
| Aprovado | Editar, Efetivar, Baixar PDF, Reprovar |
| Concluído / Finalizado | Baixar comprovante, Baixar PDF |
| Reprovado | Baixar PDF |

### 4.2 Criar novo orçamento

1. Selecione o **cliente**.
2. Selecione o **veículo** (carregado automaticamente após escolher o cliente). A cor é pré-preenchida do cadastro; ajuste se necessário.
3. Informe o **KM** atual do veículo.
4. Escolha o **responsável planejado** (opcional).
5. Selecione a **forma de pagamento** (cartão de crédito aplica 3% de taxa automaticamente).
6. Adicione os **itens** clicando em **+ Adicionar item**. Para cada item informe:
   - Descrição
   - Tipo: *Produto*, *Serviço* ou *Outros*
   - Quantidade e valor unitário (o subtotal é calculado automaticamente)
7. Clique em **Salvar orçamento**.

Após salvar, a tela exibe o texto pronto para enviar pelo WhatsApp e os botões de ação.

### 4.3 Detalhes do orçamento

Mostra todos os dados do orçamento, itens, total e texto para WhatsApp.

- **Enviar via WhatsApp**: abre o WhatsApp Web com o texto já preenchido.
- **Baixar PDF**: gera o PDF do orçamento para enviar ao cliente.
- **Efetivar**: avança o orçamento (ver seção 4.4).
- **Editar**: permite alterar cliente, veículo, itens e forma de pagamento enquanto não estiver concluído.
- **Reprovar**: marca o orçamento como reprovado.

### 4.4 Efetivar orçamento

Tela para registrar a conclusão ou aprovação do orçamento.

- **Aprovar (aguardando execução)**: muda o status para *Aprovado*. Não gera lançamento financeiro nem recibo. Use quando o cliente aprovou mas o serviço ainda não foi executado.
- **Concluir**: registra o pagamento. Informe:
  - Data de conclusão
  - Responsável pela execução (obrigatório para concluir)
  - Forma de pagamento final
  
  Ao concluir, o sistema gera automaticamente os registros de serviços e um lançamento de **entrada** no financeiro. A tela exibe o texto de confirmação de pagamento para enviar via WhatsApp e o botão para baixar o comprovante (recibo).

---

## 5. Financeiro

### 5.1 Lista de lançamentos

Exibe todas as entradas e saídas com data, descrição, categoria e valor. Lançamentos gerados por orçamentos concluídos aparecem aqui automaticamente.

### 5.2 Registrar lançamento manual

Preencha data, tipo (*Entrada* ou *Saída*), categoria, descrição e valor. Clique em **Registrar lançamento**.

---

## 6. Histórico de Serviços

Lista todos os serviços executados (gerados ao concluir orçamentos). Use o filtro de **cliente** para ver o histórico de um cliente específico.

Na tela de **Histórico do Cliente** (acessada pelo botão *Histórico* na lista de clientes) é possível filtrar por período de data.

---

## 7. Funcionários

### 7.1 Lista de funcionários

Mostra todos os funcionários com nome, cargo e situação (*Ativo* / *Inativo*). Funcionários inativos não aparecem nas seleções de responsável nos orçamentos.

### 7.2 Cadastrar funcionário

Preencha nome, telefone, cargo e observações. Clique em **Cadastrar**.

### 7.3 Ativar / Desativar

Clique no botão de status ao lado do funcionário para alternar entre *Ativo* e *Inativo*.

---

## 8. PDFs gerados

| Documento | Quando gerar | Como acessar |
|---|---|---|
| **Orçamento** | A qualquer momento após criar | Botão *Baixar PDF* nos detalhes ou na lista |
| **Comprovante (recibo)** | Somente após orçamento *Concluído* | Botão *Baixar comprovante* nos detalhes ou na lista |

---

## 9. Dicas rápidas

- A cor do veículo cadastrada no perfil do cliente é pré-preenchida ao criar o orçamento; você pode ajustá-la pontualmente sem alterar o cadastro.
- O texto para WhatsApp é gerado automaticamente com todos os itens e o valor final; basta copiar ou clicar no botão de envio.
- Para corrigir itens de um orçamento em aberto, use **Editar** — o texto do WhatsApp e o PDF são recalculados automaticamente.
- Orçamentos *Concluídos* ou *Finalizados* não podem ser editados nem reprovados.
