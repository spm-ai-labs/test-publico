// file-processor.js
const express = require('express');
const router = express.Router();
const { exec } = require('child_process');

// Vulnerabilidad 3: Inyección de comandos del sistema operativo
router.post('/process-file', (req, res) => {
  const { filename } = req.body;
  const command = `cat ./uploads/${filename}`;

  exec(command, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('Error processing file.');
    }
    res.send(stdout);
  });
});

module.exports = router;
