# ROADMAP

Roadmap do projeto Dragonite. O objetivo é implementar um homeserver Matrix funcional,
com o máximo de compatibilidade possível com o ecossistema Matrix (clientes como Element,
e outros homeservers via federação).

Fonte da especificação: https://spec.matrix.org/latest/

**Legenda:**
- `[x]` — implementado e verificado 
- `[ ]` — não implementado / não confirmado

**Obrigatórios** = necessários para o homeserver funcionar minimamente: autenticar,
criar/entrar em salas, trocar mensagens, mídia básica, e federar com outro servidor.
**Opcionais** = funcionalidades adicionais da spec; cada uma vem com uma frase sobre
onde ela agregaria valor, para ajudar a priorizar depois.

---

## Client-Server API

### Obrigatórios

- [x] GET /.well-known/matrix/client
- [x] GET /.well-known/matrix/support
- [ ] GET /.well-known/matrix/server 
- [x] GET /\_matrix/client/versions
- [X] POST /\_matrix/client/v3/register 
- [X] POST /\_matrix/client/v3/login 
- [X] GET /\_matrix/client/v3/login
- [X] POST /\_matrix/client/v3/logout
- [X] POST /\_matrix/client/v3/refresh
- [X] GET /\_matrix/client/v3/account/whoami
- [x] GET /\_matrix/client/v3/capabilities *(mock — retorna só `m.room_versions` com default/available "11")*
- [x] POST /\_matrix/client/v3/user/{userId}/filter *(mock — retorna `filter_id` fixo, sem aplicar filtro de verdade)*
- [x] GET /\_matrix/client/v3/sync *(`to_device` e `device_one_time_keys_count` implementados; `device_lists.changed/left` ainda não)*
- [X] POST /\_matrix/client/v3/createRoom 
- [X] POST /\_matrix/client/v3/rooms/{roomId}/join
- [X] POST /\_matrix/client/v3/rooms/{roomId}/leave 
- [X] POST /\_matrix/client/v3/rooms/{roomId}/invite 
- [x] PUT /\_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId} 
- [x] PUT /\_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey} 
- [X] GET /\_matrix/client/v3/rooms/{roomId}/state
- [X] GET /\_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
- [X] GET /\_matrix/client/v3/rooms/{roomId}/event/{eventId}
- [X] GET /\_matrix/client/v3/rooms/{roomId}/messages
- [ ] GET /\_matrix/client/v3/rooms/{roomId}/members
- [X] GET /\_matrix/client/v3/rooms/{roomId}/joined_members
- [x] GET /\_matrix/client/v3/profile/{userId} 
- [x] GET /\_matrix/client/v3/profile/{userId}/{keyName} 
- [x] PUT /\_matrix/client/v3/profile/{userId}/{keyName}
- [x] POST /\_matrix/media/v3/upload
- [x] GET /\_matrix/client/v1/media/download/{serverName}/{mediaId}
- [x] GET /\_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}
- [X] GET /_matrix/client/v3/room_keys/version
- [X] POST /_matrix/client/v3/room_keys/version
- [X] GET /\_matrix/client/v3/room_keys/keys
- [X] PUT /\_matrix/client/v3/room_keys/keys *(upsert last-write-wins; sem a regra de "manter a melhor chave" da spec)*
- [X] DELETE /\_matrix/client/v3/room_keys/keys
- [X] POST /_matrix/client/v3/keys/device_signing/upload
- [X] POST /_matrix/client/v3/keys/signatures/upload
- [X] POST /_matrix/client/v3/keys/upload 
- [X] POST /_matrix/client/v3/keys/query *(master_keys/self_signing_keys agora federados via POST /_matrix/federation/v1/user/keys/query; user_signing_key permanece só local, por design da spec)*
- [x] POST /_matrix/client/v3/keys/claim *(federado via POST /_matrix/federation/v1/user/keys/claim)*
- [x] GET /_matrix/client/v3/keys/changes
- [x] PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId} *(idempotência por txnId, expande device_id "*", federa via EDU m.direct_to_device pra usuários remotos)*

### Opcionais

- [ ] POST /\_matrix/client/v3/logout/all — *derrubar todas as sessões do usuário de uma vez, útil se um token vazar.*
- [ ] POST /\_matrix/client/v3/account/password — *deixar o usuário trocar a própria senha sem intervenção manual.*
- [ ] POST /\_matrix/client/v3/account/deactivate — *permitir exclusão de conta pelo próprio usuário.*
- [X] GET /\_matrix/client/v3/user/{userId}/filter/{filterId} — *(só o mock atualmente)*
- [x] DELETE /\_matrix/client/v3/profile/{userId}/{keyName} — *permite limpar displayname/avatar.*
- [ ] POST /\_matrix/client/v3/join/{roomIdOrAlias} — *permitir entrar numa sala por alias amigável, não só por room ID.*
- [ ] POST /\_matrix/client/v3/rooms/{roomId}/forget — *limpar o histórico local de uma sala já deixada, evitando que ela reapareça em syncs futuros.*
- [ ] POST /\_matrix/client/v3/rooms/{roomId}/kick — *moderação: remover um usuário problemático da sala.*
- [ ] POST /\_matrix/client/v3/rooms/{roomId}/ban — *moderação: impedir que um usuário específico volte a entrar.*
- [ ] POST /\_matrix/client/v3/rooms/{roomId}/unban — *reverter um ban.*
- [ ] PUT /\_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId} — *apagar/editar mensagens enviadas por engano ou ofensivas.*
- [X] GET /\_matrix/client/v3/joined_rooms — *atalho para listar salas do usuário sem precisar de um `/sync` completo.*
- [X] GET/PUT/DELETE /\_matrix/client/v3/directory/room/{roomAlias} — *resolver/gerenciar alias amigáveis de sala (ex: #geral:dragonite.com).*
- [X] GET/POST /\_matrix/client/v3/publicRooms — *permitir que o usuário descubra salas públicas direto pelo cliente (versão client-side do que já existe na federação).*
- [X] GET /\_matrix/client/v1/media/config — *informar ao cliente o tamanho máximo de upload, evitando uploads fadados a falhar.*
- [ ] GET /\_matrix/client/v1/media/preview_url — *gerar prévia (título/imagem/descrição) de links compartilhados no chat.*
- [X] GET/PUT /\_matrix/client/v3/user/{userId}/account_data/{type} — *guardar preferências do usuário (tags de sala, favoritos) sincronizadas entre dispositivos.*
- [X] GET/PUT /\_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type} — *igual ao acima, mas por sala (ex: marcar uma sala como silenciada).*
- [X] PUT/GET /\_matrix/client/v3/presence/{userId}/status — *mostrar status online/ausente/offline dos usuários.*
- [ ] PUT /\_matrix/client/v3/rooms/{roomId}/typing/{userId} — *indicador de "fulano está digitando...".*
- [x] POST /\_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId} *(Como está agora: mock — retorna `{}`, sem persistir nada)* — *marcar mensagens como lidas e exibir contagem de não lidas corretamente.*
- [x] POST /\_matrix/client/v3/rooms/{roomId}/read_markers *(Como está agora: mock - retorna `{}`, sem persistir nada; a spec trata `m.fully_read` via `/receipt` como uma chamada interna a este endpoint, mas como ambos são mocks isso não afeta nada por enquanto)*
- [ ] GET/PUT/DELETE /\_matrix/client/v3/devices, /devices/{deviceId} — *deixar o usuário ver e revogar sessões abertas em outros dispositivos.*
- [x] GET /\_matrix/client/v3/pushrules/ — *mock; ver seção de push abaixo pra versão real.*
- [ ] GET/PUT/DELETE /\_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId} — *regras de notificação de verdade (ex: silenciar uma sala, destacar menções), hoje só o mock vazio existe.*
- [ ] POST /\_matrix/client/v3/pushers/set e GET /pushers — *registrar um "pusher" (endpoint de push), pré-requisito pra notificações push funcionarem de ponta a ponta junto com a Push Gateway API.*
- [x] POST /\_matrix/client/v3/user_directory/search — *permite buscar usuários pelo diretório (nome/display name).*
- [x] GET /\_matrix/client/v3/thirdparty/protocols *(mock — retorna `{}`, sem bridges reais; necessário pro seletor de rede do diretório público do Element inicializar corretamente, mesmo sem integrar bridges de verdade)*
- [ ] POST /\_matrix/client/v3/search — *busca full-text de mensagens dentro do cliente.*
- [ ] POST /\_matrix/client/v3/rooms/{roomId}/report e /event/{eventId}/report — *deixar usuários denunciarem conteúdo abusivo para moderação.*
- [ ] Criptografia ponta-a-ponta (`/\_matrix/client/v3/keys/*`) — *mensagens realmente privadas entre usuários; exige gerenciamento de dispositivos e troca de chaves, escopo grande demais pro trabalho.*
- [ ] VoIP/TURN (`/\_matrix/client/v3/voip/turnServer`) — *chamadas de voz/vídeo dentro do chat.*

---

## Server-Server (Federation) API

### Obrigatórios

Rotas essenciais para duas instâncias Dragonite conseguirem federar de forma correta e
resiliente (incluindo reconciliação de estado após partições de rede).

- [X] GET /.well-known/matrix/server 
- [x] GET /\_matrix/federation/v1/version
- [x] GET /\_matrix/key/v2/server
- [x] PUT /\_matrix/federation/v1/send/{txnId} *(PDUs completos; EDUs só `m.direct_to_device` por enquanto)*
- [x] GET /\_matrix/federation/v1/backfill/{roomId}
- [X] POST /\_matrix/federation/v1/get_missing_events/{roomId} *(reconciliação de lacunas na DAG após partição/reconexão)*
- [x] GET /\_matrix/federation/v1/event/{eventId}
- [X] GET /\_matrix/federation/v1/state/{roomId} *(recuperar estado completo de uma sala ao entrar via federação)*
- [X] GET /\_matrix/federation/v1/state_ids/{roomId} *(mesma coisa, mas só IDs — usado para resolução de estado eficiente)*
- [x] GET /\_matrix/federation/v1/make_join/{roomId}/{userId}
- [x] PUT /\_matrix/federation/v2/send_join/{roomId}/{eventId}
- [x] GET /\_matrix/federation/v1/make_leave/{roomId}/{userId}
- [x] PUT /\_matrix/federation/v2/send_leave/{roomId}/{eventId}
- [x] PUT /\_matrix/federation/v2/invite/{roomId}/{eventId}
- [x] GET /\_matrix/federation/v1/query/profile
- [x] GET /\_matrix/federation/v1/publicRooms
- [x] POST /\_matrix/federation/v1/publicRooms
- [x] GET /\_matrix/federation/v1/media/download/{mediaId}
- [x] POST /\_matrix/federation/v1/user/keys/query
- [x] POST /\_matrix/federation/v1/user/keys/claim

### Opcionais

- [ ] POST /\_matrix/key/v2/query — *verificar as chaves de vários servidores remotos numa única chamada, em vez de uma requisição por servidor.*
- [ ] GET /\_matrix/key/v2/query/{serverName} — *mesma ideia, mas via notário de confiança, útil quando o servidor remoto está inacessível diretamente.*
- [ ] GET /\_matrix/federation/v1/event_auth/{roomId}/{eventId} — *obter a cadeia de autorização de um evento específico, alternativa mais granular ao `state`/`backfill` pra depurar ou validar permissões.*
- [ ] GET /\_matrix/federation/v1/timestamp_to_event/{roomId} — *"pular para uma data" numa sala, útil pra navegação de histórico longo.*
- [ ] GET /\_matrix/federation/v1/make_knock/{roomId}/{userId} e PUT /send_knock/{roomId}/{eventId} — *permitir "bater na porta" de uma sala privada pedindo pra entrar, em vez de precisar de convite direto.*
- [ ] PUT /\_matrix/federation/v1/invite/{roomId}/{eventId} — *versão legada do invite; a v2 já cobre o caso de uso, então baixa prioridade.*
- [ ] PUT /\_matrix/federation/v1/exchange_third_party_invite/{roomId} e PUT /3pid/onbind — *convidar alguém para uma sala usando só o e-mail/telefone dela, antes mesmo de ter conta no Matrix.*
- [X] GET /\_matrix/federation/v1/query/directory — *resolver um alias de sala (#nome:servidor) hospedado por outro servidor remotamente.*
- [ ] GET /\_matrix/federation/v1/query/{queryType} — *endpoint genérico de consultas federadas além de perfil/diretório.*
- [ ] GET /\_matrix/federation/v1/hierarchy/{roomId} — *navegar espaços (spaces) e sub-salas aninhadas entre servidores.*
- [ ] GET /\_matrix/federation/v1/media/thumbnail/{mediaId} — *miniatura de mídia remota via federação; hoje o download remoto já serve o arquivo original, então é só otimização de banda.*
- [ ] GET /\_matrix/federation/v1/openid/userinfo — *permitir que um serviço externo valide a identidade de um usuário via OpenID Connect emitido pelo homeserver.*
- [ ] GET /\_matrix/federation/v1/user/devices/{userId} — *lista os device IDs + stream_id de um usuário local; usado por outros servidores pra saber se precisam re-consultar `/keys/query`. `query`/`claim` já cobertos acima.
- [ ] POST /\_matrix/policy/v1/sign — *assinar políticas de moderação de conteúdo compartilhadas entre servidores (feature mais recente da spec).*

---

## Identity Service API (Opcional)

Serviço separado usado para descobrir usuários por e-mail/telefone (3PID lookup) e para
convites por e-mail antes de a pessoa ter conta. Nenhuma rota é necessária para a
federação básica funcionar — só valeria a pena se quisermos permitir buscar/convidar
contatos por e-mail ou telefone em vez de só por Matrix ID.

- [ ] GET /\_matrix/identity/versions
- [ ] GET /\_matrix/identity/v2/account
- [ ] POST /\_matrix/identity/v2/account/logout
- [ ] POST /\_matrix/identity/v2/account/register
- [ ] GET /\_matrix/identity/v2/terms
- [ ] POST /\_matrix/identity/v2/terms
- [ ] GET /\_matrix/identity/v2
- [ ] GET /\_matrix/identity/v2/pubkey/ephemeral/isvalid
- [ ] GET /\_matrix/identity/v2/pubkey/isvalid
- [ ] GET /\_matrix/identity/v2/pubkey/{keyId}
- [ ] GET /\_matrix/identity/v2/hash_details
- [ ] POST /\_matrix/identity/v2/lookup
- [ ] POST /\_matrix/identity/v2/validate/email/requestToken
- [ ] GET /\_matrix/identity/v2/validate/email/submitToken
- [ ] POST /\_matrix/identity/v2/validate/email/submitToken
- [ ] POST /\_matrix/identity/v2/validate/msisdn/requestToken
- [ ] GET /\_matrix/identity/v2/validate/msisdn/submitToken
- [ ] POST /\_matrix/identity/v2/validate/msisdn/submitToken
- [ ] POST /\_matrix/identity/v2/3pid/bind
- [ ] GET /\_matrix/identity/v2/3pid/getValidated3pid
- [ ] POST /\_matrix/identity/v2/3pid/unbind
- [ ] POST /\_matrix/identity/v2/store-invite
- [ ] POST /\_matrix/identity/v2/sign-ed25519

---

## Application Service API (Opcional)

Usado para bots/bridges (ex: integração com Telegram, IRC). Nenhuma rota necessária — só
valeria a pena se quiséssemos permitir que serviços externos controlem usuários/salas
"fantasma" dentro do Dragonite para fazer ponte com outra plataforma de chat.

- [ ] PUT /\_matrix/app/v1/transactions/{txnId} — *receber eventos que a bridge deve processar.*
- [ ] GET /\_matrix/app/v1/users/{userId} e GET /rooms/{roomAlias} — *o homeserver perguntar à bridge se um usuário/sala "fantasma" deve existir sob demanda.*
- [ ] GET /\_matrix/app/v1/thirdparty/protocol/{protocol}, /user/{protocol}, /location/{protocol} — *descoberta de metadados da plataforma em ponte (ex: listar canais do IRC disponíveis).*
- [ ] GET /\_matrix/app/v1/ping — *health-check simples do homeserver até a bridge.*

## Push Gateway API (Opcional)

Necessário apenas se quisermos notificações push de verdade (hoje `pushrules` é só mock
e não existe pusher registrado).

- [ ] POST /\_matrix/push/v1/notify — *o homeserver notifica o gateway de push (ex: FCM/APNs) quando há uma mensagem nova para um dispositivo offline.*

---

## Prioridades sugeridas (dentro dos obrigatórios que faltam)


- Bug da rota upload
- Bug na rota refresh

