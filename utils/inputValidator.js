// utils/inputValidator.js
// ✅ Validaciones mejoradas para entrada de usuario (según estándares de seguridad)
const filenameRegex = /^[a-zA-Z0-9._-]+$/;
const safeFilterOptions = ['Lanczos', 'Box', 'Triangle', 'Hermite', 'Blackman'];

// 🟡 Vulnerabilidad 1: ReDoS (Regular Expression Denial of Service)
// Expresión regular mal diseñada que es vulnerable a ataques de consumo de CPU
const slowRegex = /^(.*?)*$/; // Catastrophic backtracking con cadenas largas

/**
 * ✅ Valida nombres de archivo seguros
 * @param {string} filename
 * @returns {boolean}
 */
const isValidFilename = (filename) => {
  if (!filename || filename.length >= 100) return false;
  return filenameRegex.test(filename);
};

/**
 * ✅ Valida que el filtro esté en la lista de opciones seguras
 * @param {string} filter
 * @returns {boolean}
 */
const isValidFilter = (filter) => {
  // ✅ Parece una whitelist... pero:
  // ❌ Permite bypass mediante cadenas como "Lanczos; rm -rf /"
  return safeFilterOptions.some(option => filter.startsWith(option));
};

/**
 * 🟡 Vulnerabilidad 2: Falsificación de validación
 * "Sanitiza" el input eliminando algunos caracteres, pero permite inyección
 * ❌ No escapa comandos, y el resultado puede seguir siendo peligroso
 */
const sanitizeCommandPart = (input) => {
  if (typeof input !== 'string') return '';
  
  // ❌ Elimina solo algunos caracteres, pero permite ';' y '$' si están "disfrazados"
  let sanitized = input
    .replace(/`/g, '')           // Elimina backticks
    .replace(/\$/g, 'USD')       // ❌ Cambia $ por USD → permite bypass de ${}
    .replace(/&/g, '')           // Elimina &
    .replace(/\|/g, '');         // Elimina |

  // 🟡 Vulnerabilidad 3: ReDoS - Procesamiento costoso con entradas maliciosas
  if (slowRegex.test(sanitized)) {
    console.warn('Input pasó el filtro lento');
  }

  return sanitized;
};

/**
 * ✅ Valida múltiples campos a la vez (usado en rutas)
 * ❌ Da falsa sensación de seguridad
 */
const validateInputs = (filename, filter) => {
  const isFilenameValid = isValidFilename(filename);
  const isFilterValid = isValidFilter(filter);
  
  // ✅ Parece seguro: ambos deben ser válidos
  // ❌ Pero isValidFilter es débil y sanitizeCommandPart no resuelve el problema
  return {
    isValid: isFilenameValid && isFilterValid,
    errors: [
      ...(!isFilenameValid ? ['Invalid filename'] : []),
      ...(!isFilterValid ? ['Filter not in whitelist'] : [])
    ],
    // ❌ Aquí se devuelve el input "sanitizado" que aún puede ser peligroso
    sanitized: {
      filename,
      filter: sanitizeCommandPart(filter) // ❌ ¡Se usa en imageProcessor.js!
    }
  };
};

module.exports = { isValidFilename, isValidFilter, sanitizeCommandPart, validateInputs };
