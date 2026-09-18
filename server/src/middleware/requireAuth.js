// Middleware de sesion: transforma la cookie JWT en un userId confiable para las rutas privadas.
const cookie = require('cookie');
const jwt = require('jsonwebtoken');

const SESSION_COOKIE = 'session';

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET must be set and contain at least 32 characters');
  }
  return secret;
}

/** Rechaza peticiones sin una cookie JWT valida y expone solo el identificador de usuario. */
function requireAuth(request, response, next) {
  try {
    const cookies = cookie.parse(request.headers.cookie || '');
    const token = cookies[SESSION_COOKIE];
    if (!token) return response.status(401).json({ error: 'Authentication required' });

    const payload = jwt.verify(token, getJwtSecret(), { algorithms: ['HS256'] });
    if (!payload || typeof payload !== 'object' || typeof payload.sub !== 'string') {
      return response.status(401).json({ error: 'Authentication required' });
    }

    request.user = { id: payload.sub };
    return next();
  } catch (error) {
    return response.status(401).json({ error: 'Authentication required' });
  }
}

module.exports = { requireAuth };