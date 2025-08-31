// routes/image.js
const express = require('express');
const router = express.Router();
const imageProcessor = require('../services/imageProcessor');

// Ruta vulnerable: el parámetro 'filter' viene directamente del usuario
router.post('/process', async (req, res) => {
  const { filename, filter } = req.body;

  if (!filename || !filter) {
    return res.status(400).json({ error: 'Filename and filter are required' });
  }

  try {
    const result = await imageProcessor.applyFilter(filename, filter);
    res.json({ success: true, processedFile: result });
  } catch (err) {
    res.status(500).json({ error: 'Processing failed', details: err.message });
  }
});

module.exports = router;
