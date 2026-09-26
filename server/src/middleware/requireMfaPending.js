// Middleware de MFA pendiente: transforma la cookie "mfa" intermedia en los
// datos necesarios para verificar el segundo factor. Solo se emite despues de
// un login con Auth Hash correcto cuando la cuenta tiene MFA activo, y caduca
// en minutos; una vez verificado el codigo se limpia y se firma la sesion real.
const cookie = require('cookie');
const jwt = require('jsonwebtoken');

const MFA_COOKIE = 'mfa';

// Mismo patron que requireAuth: el secreto se exige en runtime.
function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET must be set and contain at least 32 characters');
  }
  return secret;
}

/** Rechaza peticiones sin una cookie mfa valida y expone el secreto pendiente de verificar. */
function requireMfaPending({ dbPool }) {
  return async function mfaPendingRequest(request, response, next) {
    try {
      const cookies = cookie.parse(request.headers.cookie || '');
      const token = cookies[MFA_COOKIE];
      if (!token) return response.status(401).json({ error: 'MFA verification required' });

      // El proposito 'mfa' impide que una cookie de sesion normal se reutilice
      // como credencial intermedia (y viceversa) en las rutas de verificacion.
      const payload = jwt.verify(token, getJwtSecret(), { algorithms: ['HS256'] });
      if (!payload || typeof payload !== 'object' || payload.purpose !== 'mfa'
        || typeof payload.sub !== 'string' || !Number.isInteger(payload.sv) || payload.sv < 0) {
        return response.status(401).json({ error: 'MFA verification required' });
      }

      const result = await dbPool.query(
        `SELECT session_version, mfa_enabled, mfa_secret
         FROM users WHERE id = $1`,
        [payload.sub],
      );
      const user = result.rows[0];
      // El session_version vigente invalida el reto si la contrasena cambio
      // o si el MFA se desactivo mientras esperaba el codigo.
      if (!user || user.session_version !== payload.sv || !user.mfa_enabled) {
        return response.status(401).json({ error: 'MFA verification required' });
      }

      request.user = {
        id: payload.sub,
        mfaSecret: user.mfa_secret,
      };
      return next();
    } catch (error) {
      return response.status(401).json({ error: 'MFA verification required' });
    }
  };
}

module.exports = { requireMfaPending };
