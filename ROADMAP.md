# ROADMAP

Roadmap do projeto onde algumas tasks podem ser melhor especificadas e acompanhadas.

## Roadmap de Endpoints

Endpoints essenciais para a implementação do Servidor. Fonte: https://spec.matrix.org/latest/

### Endpoints Client

**Required**: endpoints essenciais que precisam ser implementados obrigatóriamente

- [x] GET /.well-known/matrix/client
- [x] GET /.well-known/matrix/support
- [x] GET /\_matrix/client/versions
- [ ] GET /\_matrix/client/v3/login
- [ ] POST /\_matrix/client/v3/login
- [ ] POST /\_matrix/client/v3/logout
- [ ] POST /\_matrix/client/v3/refresh
- [ ] GET /\_matrix/client/v3/sync
- [ ] POST /\_matrix/client/v3/createRoom
- [ ] POST /\_matrix/client/v3/rooms/{roomId}/join
- [ ] POST /\_matrix/client/v3/rooms/{roomId}/leave
- [ ] PUT /\_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
- [ ] PUT /\_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}

#### Media

- [ ] GET /\_matrix/client/v3/profile/{userId}/displayname
- [ ] PUT /\_matrix/client/v3/profile/{userId}/displayname
- [ ] POST /\_matrix/media/v3/upload
- [ ] GET /\_matrix/media/v3/download/{serverName}/{mediaId}

### Server Endpoints

- [ ] GET /.well-known/matrix/server
- [ ] GET /\_matrix/federation/v1/version
- [ ] GET /\_matrix/key/v2/server
- [ ] POST /\_matrix/key/v2/query
- [ ] GET /\_matrix/key/v2/query/{serverName}
- [ ] PUT /\_matrix/federation/v1/send/{txnId}
- [ ] GET /\_matrix/federation/v1/event_auth/{roomId}/{eventId}
- [ ] GET /\_matrix/federation/v1/backfill/{roomId}
- [ ] POST /\_matrix/federation/v1/get_missing_events/{roomId}
- [ ] GET /\_matrix/federation/v1/event/{eventId}
- [ ] GET /\_matrix/federation/v1/state/{roomId}
- [ ] GET /\_matrix/federation/v1/state_ids/{roomId}
- [ ] GET /\_matrix/federation/v1/timestamp_to_event/{roomId}
- [ ] GET /\_matrix/federation/v1/make_join/{roomId}/{userId}
- [ ] PUT /\_matrix/federation/v2/send_join/{roomId}/{eventId}
- [ ] GET /\_matrix/federation/v1/make_knock/{roomId}/{userId}
- [ ] PUT /\_matrix/federation/v1/send_knock/{roomId}/{eventId}
- [ ] PUT /\_matrix/federation/v1/invite/{roomId}/{eventId}
- [ ] PUT /\_matrix/federation/v2/invite/{roomId}/{eventId}
- [ ] GET /\_matrix/federation/v1/make_leave/{roomId}/{userId}
- [ ] PUT /\_matrix/federation/v2/send_leave/{roomId}/{eventId}
- [ ] PUT /\_matrix/federation/v1/3pid/onbind
- [ ] PUT /\_matrix/federation/v1/exchange_third_party_invite/{roomId}
- [ ] GET /\_matrix/federation/v1/publicRooms
- [ ] POST /\_matrix/federation/v1/publicRooms
- [ ] GET /\_matrix/federation/v1/hierarchy/{roomId}
- [ ] GET /\_matrix/federation/v1/query/directory
- [ ] GET /\_matrix/federation/v1/query/profile
- [ ] GET /\_matrix/federation/v1/query/{queryType}
- [ ] GET /\_matrix/federation/v1/openid/userinfo
- [ ] GET /\_matrix/federation/v1/user/devices/{userId}
- [ ] POST /\_matrix/federation/v1/user/keys/claim
- [ ] POST /\_matrix/federation/v1/user/keys/query
- [ ] GET /\_matrix/federation/v1/media/download/{mediaId}
- [ ] GET /\_matrix/federation/v1/media/thumbnail/{mediaId}
- [ ] POST /\_matrix/policy/v1/sign

### Identity Endpoints

Opcional, usado para descobrir usuários.

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

### Outras APIs

Podemos implementar as API de Gateway para liberar _push notifications_.
