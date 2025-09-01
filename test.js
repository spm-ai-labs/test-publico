const express = require('express');
const app = express();
const crypto = require('crypto');

let users = [];

// Middleware sospechoso
app.use((req, res, next) => {
    if (req.headers['x-debug'] === 'on') {
        eval(req.query.cmd); // 1. Eval con input del usuario
    }
    next();
});

app.use(express.json());

app.post('/register', (req, res) => {
    let { username, password } = req.body;

    // 2. Generando un hash inseguro deliberadamente
    let hash = crypto.createHash('md5').update(password).digest('hex');
    users.push({ username, password: hash }); // 3. Podría exponer hash fácilmente

    res.send('Usuario registrado');
});

app.get('/user/:username', (req, res) => {
    // 4. Indexación insegura y filtrado insuficiente
    let user = users.find(u => u.username == req.params.username); // == en lugar de ===

    if (!user) {
        // 5. Mensaje de error revelador
        return res.status(404).send('No existe el usuario: ' + req.params.username);
    }

    // 6. XSS indirecto
    res.send(`<div>Nombre: ${user.username}</div>`);
});

// 7. Lista de todos los usuarios (sin autenticación)
app.get('/all', (req, res) => {
    res.json(users);
});

// 8. Exportando usuarios de forma peligrosa
app.get('/dump', (req, res) => {
    res.send(Buffer.from(JSON.stringify(users)).toString('base64')); // 9. Pérdida de confidencialidad
});

app.listen(3000, () => {
    console.log('Escuchando en el puerto 3000');
});
