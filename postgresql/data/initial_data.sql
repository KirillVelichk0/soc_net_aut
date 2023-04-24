INSERT INTO public.users_main_table(uid, email, pass_h, salt)
VALUES (0, 'cirill@live.ru', 'QERDSFqewr', 'adsewqr')
ON CONFLICT (uid)
DO NOTHING;
