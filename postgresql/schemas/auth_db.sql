--
-- PostgreSQL database dump
--

-- Dumped from database version 15.2
-- Dumped by pg_dump version 15.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: postgres
--

-- *not* creating schema, since initdb creates it
DROP SCHEMA IF EXISTS public CASCADE;

CREATE SCHEMA IF NOT EXISTS public;

--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: postgres
--

COMMENT ON SCHEMA public IS '';


--
-- Name: delete_old_preusers_func(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.delete_old_preusers_func() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
delete from users_second_table 
where NOW() > max_ts;
return new;
END; $$;


ALTER FUNCTION public.delete_old_preusers_func() OWNER TO postgres;

--
-- Name: deleteoldtokensfunc(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.deleteoldtokensfunc() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
delete from users_token_info
where extract(epoch from NOW()) > time_limit;
return NEW;
END; $$;


ALTER FUNCTION public.deleteoldtokensfunc() OWNER TO postgres;

--
-- Name: insert_token(bigint, bigint, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.insert_token("uidP" bigint, "time_limitP" bigint, "open_keyP" text) RETURNS bigint
    LANGUAGE plpgsql
    AS $$declare
tidP int8;
begin
with inserting as 
(insert into users_tokens_info(uid, time_limit, open_key)
VALUES("uidP", "time_limitP", "open_keyP")
returning tid)
select tid into tidP from  inserting;
return tidP;

end; $$;


ALTER FUNCTION public.insert_token("uidP" bigint, "time_limitP" bigint, "open_keyP" text) OWNER TO postgres;

--
-- Name: try_register(character varying, character, character, character); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.try_register(emailp character varying, pass_hp character, saltp character, verifp character) RETURNS bigint
    LANGUAGE plpgsql
    AS $$
DECLARE
max_tsP timestamptz;
uidP bigint;
BEGIN
if exists(select * from users_main_table where email = emailP) then
return -1;
else
max_tsP := NOW() + Interval '15 minutes';
with inserting as
(insert into users_second_table(email, pass_h, salt, verif, max_ts)
VALUES(emailP, pass_hP, saltP, verifP, max_tsP)
returning uid)
select uid into uidP from inserting;
return uidP;
end if;
END; $$;


ALTER FUNCTION public.try_register(emailp character varying, pass_hp character, saltp character, verifp character) OWNER TO postgres;

--
-- Name: try_verify(bigint, character); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.try_verify(idp bigint, verifp character) RETURNS character varying
    LANGUAGE plpgsql
    AS $$
DECLARE
emailV varchar(32);
verifV char(32);
passV char(32);
saltV char(32);
maxV timestamptz;
is_exists bool;
is_uncorrect bool;
is_old bool;
BEGIN
select email, verif, pass_h, salt, max_ts 
into emailV, verifV, passV, saltV, maxV
from users_second_table where uid = idP;
if not found then
	return 'Uncorrect id';
end if;
is_exists := exists (select * from users_main_table where email = emailV);
is_uncorrect := verifV <> verifP;
is_old := (NOW() > maxV);
if is_exists then
	delete from users_second_table where email = emailV;
	return 'Account with this email already exists';
elsif is_uncorrect then
	return 'Uncorrect verifying code';
elsif is_old then
	return 'Code is old';
else
	insert into users_main_table (email, pass_h, salt)
	values (emailV, passV, saltV);
	delete from users_second_table where email = emailV;
	return 'Registration done';
end if;
END; $$;


ALTER FUNCTION public.try_verify(idp bigint, verifp character) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: users_main_table; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users_main_table (
    uid bigint NOT NULL,
    email character varying(32),
    pass_h character(32),
    salt character(32)
);


ALTER TABLE public.users_main_table OWNER TO postgres;

--
-- Name: users_main_table_uid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_main_table_uid_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_main_table_uid_seq OWNER TO postgres;

--
-- Name: users_main_table_uid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_main_table_uid_seq OWNED BY public.users_main_table.uid;


--
-- Name: users_second_table; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users_second_table (
    uid bigint NOT NULL,
    email character varying(32),
    pass_h character(32),
    salt character(32),
    verif character(32),
    max_ts timestamp with time zone
);


ALTER TABLE public.users_second_table OWNER TO postgres;

--
-- Name: users_second_table_uid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_second_table_uid_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_second_table_uid_seq OWNER TO postgres;

--
-- Name: users_second_table_uid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_second_table_uid_seq OWNED BY public.users_second_table.uid;


--
-- Name: users_tokens_info; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users_tokens_info (
    tid bigint NOT NULL,
    uid bigint,
    time_limit bigint,
    open_key text
);


ALTER TABLE public.users_tokens_info OWNER TO postgres;

--
-- Name: users_tokens_info_tid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_tokens_info_tid_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_tokens_info_tid_seq OWNER TO postgres;

--
-- Name: users_tokens_info_tid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_tokens_info_tid_seq OWNED BY public.users_tokens_info.tid;


--
-- Name: users_main_table uid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_main_table ALTER COLUMN uid SET DEFAULT nextval('public.users_main_table_uid_seq'::regclass);


--
-- Name: users_second_table uid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_second_table ALTER COLUMN uid SET DEFAULT nextval('public.users_second_table_uid_seq'::regclass);


--
-- Name: users_tokens_info tid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_tokens_info ALTER COLUMN tid SET DEFAULT nextval('public.users_tokens_info_tid_seq'::regclass);


--
-- Name: users_main_table users_main_table_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_main_table
    ADD CONSTRAINT users_main_table_email_key UNIQUE (email);


--
-- Name: users_main_table users_main_table_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_main_table
    ADD CONSTRAINT users_main_table_pkey PRIMARY KEY (uid);


--
-- Name: users_second_table users_second_table_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_second_table
    ADD CONSTRAINT users_second_table_pkey PRIMARY KEY (uid);


--
-- Name: users_tokens_info users_tokens_info_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_tokens_info
    ADD CONSTRAINT users_tokens_info_pkey PRIMARY KEY (tid);


--
-- Name: email_i; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX email_i ON public.users_main_table USING btree (email);


--
-- Name: email_si; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX email_si ON public.users_second_table USING btree (email);


--
-- Name: max_tsi; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX max_tsi ON public.users_second_table USING btree (max_ts);


--
-- Name: tokenlimi; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX tokenlimi ON public.users_tokens_info USING btree (time_limit);


--
-- Name: users_second_table delete_old_preusers; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER delete_old_preusers AFTER INSERT ON public.users_second_table FOR EACH STATEMENT EXECUTE FUNCTION public.delete_old_preusers_func();


--
-- Name: users_tokens_info deleteoldtokens; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER deleteoldtokens AFTER INSERT ON public.users_tokens_info FOR EACH STATEMENT EXECUTE FUNCTION public.deleteoldtokensfunc();


--
-- Name: users_tokens_info users_tokens_info_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_tokens_info
    ADD CONSTRAINT users_tokens_info_uid_fkey FOREIGN KEY (uid) REFERENCES public.users_main_table(uid);


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;


--
-- PostgreSQL database dump complete
--
