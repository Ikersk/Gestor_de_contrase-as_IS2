// Middleware de sesion: transforma la cookie JWT en un userId confiable para las rutas privadas.
const cookie = require('cookie');
const jwt = require('jsonwebtoken');

const SESSION_COOKIE = 'session';

// El secreto se exige en runtime para evitar firmar sesiones con una configuración débil.
function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET must be set and contain at least 32 characters');
  }
  return secret;
}

/** Rechaza peticiones sin una cookie JWT valida y expone solo el identificador de usuario. */
function requireAuth({ dbPool }) {
  return async function authenticatedRequest(request, response, next) {
    try {
    // La cookie httpOnly solo se interpreta en el servidor; el cliente nunca lee el JWT.
    const cookies = cookie.parse(request.headers.cookie || '');
    const token = cookies[SESSION_COOKIE];
    if (!token) return response.status(401).json({ error: 'Authentication required' });

    // Limitar el algoritmo evita aceptar tokens firmados con una familia no prevista.
    const payload = jwt.verify(token, getJwtSecret(), { algorithms: ['HS256'] });
    if (!payload || typeof payload !== 'object' || typeof payload.sub !== 'string'
      || !Number.isInteger(payload.sv) || payload.sv < 0) {
      return response.status(401).json({ error: 'Authentication required' });
    }

    const result = await dbPool.query(
      'SELECT session_version FROM users WHERE id = $1',
      [payload.sub],
    );
    if (!result.rows[0] || result.rows[0].session_version !== payload.sv) {
      return response.status(401).json({ error: 'Authentication required' });
    }

    request.user = { id: payload.sub };
    return next();
    } catch (error) {
      return response.status(401).json({ error: 'Authentication required' });
    }
  }
}

module.exports = { requireAuth };