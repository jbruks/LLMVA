-- Table: sch01.messages

-- DROP TABLE IF EXISTS sch01.messages;

CREATE TABLE IF NOT EXISTS sch01.messages
(
    id integer NOT NULL DEFAULT nextval('sch01.messages_id_seq'::regclass),
    sender character varying(255) COLLATE pg_catalog."default",
    receiver character varying(255) COLLATE pg_catalog."default",
    content text COLLATE pg_catalog."default",
    "timestamp" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    read boolean DEFAULT false,
    task_id bigint,
    task_type character varying(30) COLLATE pg_catalog."default",
    CONSTRAINT messages_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS sch01.messages
    OWNER to postgres;