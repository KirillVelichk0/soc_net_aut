PGDMP             	            {            social_network_3c #   14.7 (Ubuntu 14.7-0ubuntu0.22.04.1) #   14.7 (Ubuntu 14.7-0ubuntu0.22.04.1) (    =           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            >           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            ?           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            @           1262    16395    social_network_3c    DATABASE     f   CREATE DATABASE social_network_3c WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'ru_RU.UTF-8';
 !   DROP DATABASE social_network_3c;
                postgres    false                        2615    2200    public    SCHEMA        CREATE SCHEMA public;
    DROP SCHEMA public;
                postgres    false            A           0    0    SCHEMA public    COMMENT     6   COMMENT ON SCHEMA public IS 'standard public schema';
                   postgres    false    3            �            1255    16562    delete_old_preusers_func()    FUNCTION     �   CREATE FUNCTION public.delete_old_preusers_func() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
delete from users_second_table 
where NOW() > max_ts;
return new;
END; $$;
 1   DROP FUNCTION public.delete_old_preusers_func();
       public          postgres    false    3            �            1255    16559    deleteoldtokensfunc()    FUNCTION     �   CREATE FUNCTION public.deleteoldtokensfunc() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
delete from users_token_info
where extract(epoch from NOW()) > time_limit;
return NEW;
END; $$;
 ,   DROP FUNCTION public.deleteoldtokensfunc();
       public          postgres    false    3            �            1255    16523 "   insert_token(bigint, bigint, text)    FUNCTION     e  CREATE FUNCTION public.insert_token("uidP" bigint, "time_limitP" bigint, "open_keyP" text) RETURNS bigint
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
 Z   DROP FUNCTION public.insert_token("uidP" bigint, "time_limitP" bigint, "open_keyP" text);
       public          postgres    false    3            �            1255    16556 @   try_register(character varying, character, character, character)    FUNCTION     (  CREATE FUNCTION public.try_register(emailp character varying, pass_hp character, saltp character, verifp character) RETURNS bigint
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
 s   DROP FUNCTION public.try_register(emailp character varying, pass_hp character, saltp character, verifp character);
       public          postgres    false    3            �            1255    16558    try_verify(bigint, character)    FUNCTION     �  CREATE FUNCTION public.try_verify(idp bigint, verifp character) RETURNS character varying
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
 ?   DROP FUNCTION public.try_verify(idp bigint, verifp character);
       public          postgres    false    3            �            1259    16409    users_main_table    TABLE     �   CREATE TABLE public.users_main_table (
    uid bigint NOT NULL,
    email character varying(32),
    pass_h character(32),
    salt character(32)
);
 $   DROP TABLE public.users_main_table;
       public         heap    postgres    false    3            �            1259    16408    users_main_table_uid_seq    SEQUENCE     �   CREATE SEQUENCE public.users_main_table_uid_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 /   DROP SEQUENCE public.users_main_table_uid_seq;
       public          postgres    false    210    3            B           0    0    users_main_table_uid_seq    SEQUENCE OWNED BY     U   ALTER SEQUENCE public.users_main_table_uid_seq OWNED BY public.users_main_table.uid;
          public          postgres    false    209            �            1259    16421    users_second_table    TABLE     �   CREATE TABLE public.users_second_table (
    uid bigint NOT NULL,
    email character varying(32),
    pass_h character(32),
    salt character(32),
    verif character(32),
    max_ts timestamp with time zone
);
 &   DROP TABLE public.users_second_table;
       public         heap    postgres    false    3            �            1259    16420    users_second_table_uid_seq    SEQUENCE     �   CREATE SEQUENCE public.users_second_table_uid_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 1   DROP SEQUENCE public.users_second_table_uid_seq;
       public          postgres    false    212    3            C           0    0    users_second_table_uid_seq    SEQUENCE OWNED BY     Y   ALTER SEQUENCE public.users_second_table_uid_seq OWNED BY public.users_second_table.uid;
          public          postgres    false    211            �            1259    16445    users_tokens_info    TABLE     }   CREATE TABLE public.users_tokens_info (
    tid bigint NOT NULL,
    uid bigint,
    time_limit bigint,
    open_key text
);
 %   DROP TABLE public.users_tokens_info;
       public         heap    postgres    false    3            �            1259    16444    users_tokens_info_tid_seq    SEQUENCE     �   CREATE SEQUENCE public.users_tokens_info_tid_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.users_tokens_info_tid_seq;
       public          postgres    false    3    214            D           0    0    users_tokens_info_tid_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.users_tokens_info_tid_seq OWNED BY public.users_tokens_info.tid;
          public          postgres    false    213            �           2604    16412    users_main_table uid    DEFAULT     |   ALTER TABLE ONLY public.users_main_table ALTER COLUMN uid SET DEFAULT nextval('public.users_main_table_uid_seq'::regclass);
 C   ALTER TABLE public.users_main_table ALTER COLUMN uid DROP DEFAULT;
       public          postgres    false    210    209    210            �           2604    16424    users_second_table uid    DEFAULT     �   ALTER TABLE ONLY public.users_second_table ALTER COLUMN uid SET DEFAULT nextval('public.users_second_table_uid_seq'::regclass);
 E   ALTER TABLE public.users_second_table ALTER COLUMN uid DROP DEFAULT;
       public          postgres    false    211    212    212            �           2604    16448    users_tokens_info tid    DEFAULT     ~   ALTER TABLE ONLY public.users_tokens_info ALTER COLUMN tid SET DEFAULT nextval('public.users_tokens_info_tid_seq'::regclass);
 D   ALTER TABLE public.users_tokens_info ALTER COLUMN tid DROP DEFAULT;
       public          postgres    false    213    214    214            6          0    16409    users_main_table 
   TABLE DATA           D   COPY public.users_main_table (uid, email, pass_h, salt) FROM stdin;
    public          postgres    false    210   �4       8          0    16421    users_second_table 
   TABLE DATA           U   COPY public.users_second_table (uid, email, pass_h, salt, verif, max_ts) FROM stdin;
    public          postgres    false    212   #5       :          0    16445    users_tokens_info 
   TABLE DATA           K   COPY public.users_tokens_info (tid, uid, time_limit, open_key) FROM stdin;
    public          postgres    false    214   n5       E           0    0    users_main_table_uid_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.users_main_table_uid_seq', 2, true);
          public          postgres    false    209            F           0    0    users_second_table_uid_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.users_second_table_uid_seq', 2, true);
          public          postgres    false    211            G           0    0    users_tokens_info_tid_seq    SEQUENCE SET     G   SELECT pg_catalog.setval('public.users_tokens_info_tid_seq', 1, true);
          public          postgres    false    213            �           2606    16531 +   users_main_table users_main_table_email_key 
   CONSTRAINT     g   ALTER TABLE ONLY public.users_main_table
    ADD CONSTRAINT users_main_table_email_key UNIQUE (email);
 U   ALTER TABLE ONLY public.users_main_table DROP CONSTRAINT users_main_table_email_key;
       public            postgres    false    210            �           2606    16416 &   users_main_table users_main_table_pkey 
   CONSTRAINT     e   ALTER TABLE ONLY public.users_main_table
    ADD CONSTRAINT users_main_table_pkey PRIMARY KEY (uid);
 P   ALTER TABLE ONLY public.users_main_table DROP CONSTRAINT users_main_table_pkey;
       public            postgres    false    210            �           2606    16428 *   users_second_table users_second_table_pkey 
   CONSTRAINT     i   ALTER TABLE ONLY public.users_second_table
    ADD CONSTRAINT users_second_table_pkey PRIMARY KEY (uid);
 T   ALTER TABLE ONLY public.users_second_table DROP CONSTRAINT users_second_table_pkey;
       public            postgres    false    212            �           2606    16452 (   users_tokens_info users_tokens_info_pkey 
   CONSTRAINT     g   ALTER TABLE ONLY public.users_tokens_info
    ADD CONSTRAINT users_tokens_info_pkey PRIMARY KEY (tid);
 R   ALTER TABLE ONLY public.users_tokens_info DROP CONSTRAINT users_tokens_info_pkey;
       public            postgres    false    214            �           1259    16532    email_i    INDEX     L   CREATE UNIQUE INDEX email_i ON public.users_main_table USING btree (email);
    DROP INDEX public.email_i;
       public            postgres    false    210            �           1259    16539    email_si    INDEX     H   CREATE INDEX email_si ON public.users_second_table USING btree (email);
    DROP INDEX public.email_si;
       public            postgres    false    212            �           1259    16554    max_tsi    INDEX     H   CREATE INDEX max_tsi ON public.users_second_table USING btree (max_ts);
    DROP INDEX public.max_tsi;
       public            postgres    false    212            �           1259    16561 	   tokenlimi    INDEX     M   CREATE INDEX tokenlimi ON public.users_tokens_info USING btree (time_limit);
    DROP INDEX public.tokenlimi;
       public            postgres    false    214            �           2620    16563 &   users_second_table delete_old_preusers    TRIGGER     �   CREATE TRIGGER delete_old_preusers AFTER INSERT ON public.users_second_table FOR EACH STATEMENT EXECUTE FUNCTION public.delete_old_preusers_func();
 ?   DROP TRIGGER delete_old_preusers ON public.users_second_table;
       public          postgres    false    230    212            �           2620    16560 !   users_tokens_info deleteoldtokens    TRIGGER     �   CREATE TRIGGER deleteoldtokens AFTER INSERT ON public.users_tokens_info FOR EACH STATEMENT EXECUTE FUNCTION public.deleteoldtokensfunc();
 :   DROP TRIGGER deleteoldtokens ON public.users_tokens_info;
       public          postgres    false    214    229            �           2606    16453 ,   users_tokens_info users_tokens_info_uid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.users_tokens_info
    ADD CONSTRAINT users_tokens_info_uid_fkey FOREIGN KEY (uid) REFERENCES public.users_main_table(uid);
 V   ALTER TABLE ONLY public.users_tokens_info DROP CONSTRAINT users_tokens_info_uid_fkey;
       public          postgres    false    214    210    3231            6      x�3�L,J"�������=... *�      8   ;   x�3�LN�LT�8K)($�����X��P��P��������X������R���+F��� h�e      :      x������ � �     