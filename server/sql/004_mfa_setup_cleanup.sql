-- Limpieza de secretos MFA pendientes nunca confirmados.
--
-- POST /mfa/setup deja mfa_secret + mfa_setup_at con mfa_enabled = FALSE hasta
-- que el usuario confirma el alta en /mfa/enable. Si abandona el flujo, el
-- secreto queda en la BD sin uso. Este purga los pendientes con mas de 15
-- minutos (la ventana de confirmacion que ahora exige el servidor); los
-- setups activos de menos de 15 minutos se conservan.
UPDATE users
   SET mfa_secret = NULL,
       mfa_setup_at = NULL
 WHERE mfa_enabled = FALSE
   AND mfa_secret IS NOT NULL
   AND (mfa_setup_at IS NULL OR mfa_setup_at < NOW() - INTERVAL '15 minutes');
