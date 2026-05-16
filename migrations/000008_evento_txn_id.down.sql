-- remove a constraint antes da coluna (dependência)
ALTER TABLE evento
    DROP CONSTRAINT IF EXISTS uq_evento_sender_txn;

ALTER TABLE evento
    DROP COLUMN IF EXISTS txn_id;