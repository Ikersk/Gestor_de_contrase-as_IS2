// CRUD de blobs cifrados: esta ruta nunca interpreta el contenido de una credencial.
const express = require('express');
const { requireAuth } = require('../middleware/requireAuth');
const { parsePayload, vaultItemSchema } = require('../validation');

function parseItemId(value) {
  return typeof value === 'string' && /^[1-9]\d*$/.test(value) ? value : null;
}

/** Crea las rutas privadas de vault usando el userId verificado por requireAuth. */
function createVaultRouter({ dbPool }) {
  const router = express.Router();
  router.use(requireAuth({ dbPool }));

  // GET /api/vault: devuelve solo blobs cifrados pertenecientes al usuario de la sesion.
  router.get('/', async (request, response, next) => {
    try {
      const result = await dbPool.query(
        `SELECT id, iv, ciphertext, created_at, updated_at
         FROM vault_items WHERE user_id = $1 ORDER BY id`,
        [request.user.id],
      );
      return response.json(result.rows.map((item) => ({
        id: item.id,
        iv: item.iv,
        ciphertext: item.ciphertext,
        createdAt: item.created_at,
        updatedAt: item.updated_at,
      })));
    } catch (error) {
      return next(error);
    }
  });

  // POST /api/vault: guarda un nuevo IV y ciphertext sin descifrarlos en el servidor.
  router.post('/', async (request, response, next) => {
    const payload = parsePayload(vaultItemSchema, request.body);
    if (!payload) {
      return response.status(400).json({ error: 'Invalid vault item payload' });
    }

    try {
      const result = await dbPool.query(
        `INSERT INTO vault_items (user_id, iv, ciphertext)
         VALUES ($1, $2, $3) RETURNING id`,
        [request.user.id, payload.iv, payload.ciphertext],
      );
      return response.status(201).json({ id: result.rows[0].id });
    } catch (error) {
      return next(error);
    }
  });

  // PUT /api/vault/:id: actualiza solo si el item pertenece al usuario autenticado.
  router.put('/:id', async (request, response, next) => {
    const itemId = parseItemId(request.params.id);
    const payload = parsePayload(vaultItemSchema, request.body);
    if (!itemId || !payload) {
      return response.status(400).json({ error: 'Invalid vault item payload' });
    }

    try {
      const result = await dbPool.query(
        `UPDATE vault_items
         SET iv = $1, ciphertext = $2, updated_at = CURRENT_TIMESTAMP
         WHERE id = $3 AND user_id = $4`,
        [payload.iv, payload.ciphertext, itemId, request.user.id],
      );
      if (result.rowCount === 0) return response.sendStatus(404);
      return response.sendStatus(204);
    } catch (error) {
      return next(error);
    }
  });

  // DELETE /api/vault/:id: borra solo el item del usuario autenticado.
  router.delete('/:id', async (request, response, next) => {
    const itemId = parseItemId(request.params.id);
    if (!itemId) return response.status(400).json({ error: 'Invalid vault item id' });

    try {
      const result = await dbPool.query(
        'DELETE FROM vault_items WHERE id = $1 AND user_id = $2',
        [itemId, request.user.id],
      );
      if (result.rowCount === 0) return response.sendStatus(404);
      return response.sendStatus(204);
    } catch (error) {
      return next(error);
    }
  });

  router.use((error, _request, response, _next) => {
    response.status(500).json({ error: 'Internal server error' });
  });

  return router;
}

module.exports = { createVaultRouter };