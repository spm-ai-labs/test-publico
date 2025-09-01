// user-auth.js
const express = require('express');
const app = express();
const crypto = require('crypto');

app.use(express.json());

app.get('/login', (req, res) => {
  // Vulnerabilidad 1: Inyección de comando a través de eval
  const userInput = req.query.password;
  if (userInput) {
    eval(`console.log('${userInput}')`);
  }
  res.send('Login endpoint');
});

app.post('/register', (req, res) => {
  let { username, password } = req.body;

  // Vulnerabilidad 2: Uso de un hash débil (MD5)
  let hash = crypto.createHash('md5').update(password).digest('hex');
  res.send(`User ${username} registered with hash: ${hash}`);
});
