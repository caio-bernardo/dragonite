DROP INDEX IF EXISTS idx_event_edges_room_id;
DROP INDEX IF EXISTS idx_event_edges_prev_event_id;

DROP TABLE IF EXISTS Aresta_Evento;

DROP INDEX IF EXISTS idx_events_stream_ordering;
DROP INDEX IF EXISTS idx_events_room_id;
DROP INDEX IF EXISTS idx_events_room_state;

DROP TABLE IF EXISTS Evento;
