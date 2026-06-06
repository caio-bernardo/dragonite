DROP INDEX IF EXISTS idx_dispositivo_ultimo_ts_visto;
DROP INDEX IF EXISTS idx_dispositivo_refresh_token;

DROP TABLE IF EXISTS Dispositivo;
DROP TABLE IF EXISTS AccountData;

DROP TABLE IF EXISTS Profile;

DROP TABLE IF EXISTS Usuario;
DROP DOMAIN USUARIO_LOCALPART_T;
