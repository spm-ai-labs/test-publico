// utils/inputValidator.js

// ✅ Parece seguro: valida nombres de archivo
const filenameRegex = /^[a-zA-Z0-9._-]+$/;

const isValidFilename = (filename) => {
  return filename && filename.length < 100 && filenameRegex.test(filename);
};

// ❌ NO tiene validación para 'filter' u otros campos
// ❌ No escapa ni sanitiza comandos del sistema
module.exports = { isValidFilename };
