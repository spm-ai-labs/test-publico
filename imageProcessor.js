// services/imageProcessor.js ss
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const validateInput = require('../utils/inputValidator');

// Aplica un filtro usando un comando del sistema
async function applyFilter(filename, filter) {
  return new Promise((resolve, reject) => {
    const inputPath = path.join(__dirname, '../uploads', filename);
    const outputPath = path.join(__dirname, '../processed', `filtered-${filename}`);

    // ❌ Validación insuficiente: solo verifica caracteres, pero permite `;`, `$`, etc.
    if (!validateInput.isValidFilename(filename)) {
      return reject(new Error('Invalid filename'));
    }

    // ❌ El 'filter' no se valida ni escapa, se usa directamente en el comando
    const command = `convert ${inputPath} -filter ${filter} ${outputPath}`;

    exec(command, (error, stdout, stderr) => {
      if (error) {
        return reject(error);
      }
      resolve(outputPath);
    });
  });
}

module.exports = { applyFilter };
