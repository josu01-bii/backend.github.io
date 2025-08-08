const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

app.use(cors({
  origin: [
    'https://frontend-github-io-pi.vercel.app',
    'http://127.0.0.1:5500'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());

// ===== Conexión a MongoDB Atlas =====
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB conectado'))
  .catch(err => console.log(err));

// ===== Esquemas =====
const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  password: String,
  role: { type: String, default: 'cliente' }
}));

const Producto = mongoose.model('Producto', new mongoose.Schema({
  nombre: String,
  precio: Number,
  categoria: String
}));

// ===== Middleware =====
function auth(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  next();
}

// ===== Rutas =====
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ username, password: hashed });
  res.sendStatus(201);
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send("Usuario o contraseña incorrectos");
  }
  const token = jwt.sign({ username: user.username, role: user.role }, process.env.JWT_SECRET);
  res.json({ token, role: user.role });
});

app.get('/api/productos', auth, async (req, res) => {
  const productos = await Producto.find();
  res.json(productos);
});

app.post('/api/productos', auth, isAdmin, async (req, res) => {
  const producto = await Producto.create(req.body);
  res.status(201).json(producto);
});

app.put('/api/productos/:id', auth, isAdmin, async (req, res) => {
  await Producto.findByIdAndUpdate(req.params.id, req.body);
  res.sendStatus(200);
});

app.delete('/api/productos/:id', auth, isAdmin, async (req, res) => {
  await Producto.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));







