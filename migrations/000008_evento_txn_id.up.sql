-- txn_id: identificador de transação enviado pelo cliente para garantir idempotência
ALTER TABLE evento
    ADD COLUMN IF NOT EXISTS txn_id VARCHAR(255);

-- garante unicidade por sender: dois usuários diferentes podem usar o mesmo txn_id
ALTER TABLE evento
    ADD CONSTRAINT uq_evento_sender_txn UNIQUE (fk_id_sender, txn_id);