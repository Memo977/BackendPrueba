const express = require('express');
const router = express.Router();
const Restricted_users = require('../models/restricted_usersModel');

/**
 * Obtener información básica de perfiles (solo datos públicos)
 * GET /api/public/profiles
 */
router.get('/profiles', async (req, res) => {
  try {
    // Solo devolver información no sensible de los perfiles
    const profiles = await Restricted_users.find({}, { 
      full_name: 1, 
      avatar: 1 
    });
    
    res.status(200).json(profiles);
  } catch (error) {
    console.error('Error al obtener perfiles públicos:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

/**
 * Verificar PIN (usado en la pantalla de selección de perfiles)
 * POST /api/public/verify-pin
 */
router.post('/verify-pin', async (req, res) => {
  try {
    const { profileId, pin } = req.body;
    
    if (!profileId || !pin) {
      return res.status(400).json({ error: 'Se requiere ID de perfil y PIN' });
    }
    
    const profile = await Restricted_users.findById(profileId);
    
    if (!profile) {
      return res.status(404).json({ error: 'Perfil no encontrado' });
    }
    
    if (profile.pin !== pin) {
      return res.status(401).json({ error: 'PIN incorrecto' });
    }
    
    // Devolver solo información básica del perfil (no el PIN)
    res.status(200).json({
      id: profile._id,
      name: profile.full_name,
      avatar: profile.avatar
    });
    
  } catch (error) {
    console.error('Error al verificar PIN:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

module.exports = router;