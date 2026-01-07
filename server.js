// server.js
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Enable CORS for frontend
app.use(cors({
  origin: 'http://localhost:5173',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '45478690',
  database: process.env.DB_NAME || 'Admin'
});

db.connect(err => {
  if (err) throw err;
  console.log('MySQL connected...');
});

// Middleware: Verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET || 'secretkey', (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// Middleware: Admin-only access
const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access only' });
  next();
};

// Register (for testing)
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.query(
    'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
    [username, hashedPassword, role],
    (err, result) => {
      if (err) return res.status(500).json(err);
      res.json({ message: 'User registered!' });
    }
  );
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, result) => {
    if (err) return res.status(500).json(err);
    if (result.length === 0) return res.status(404).json({ message: 'User not found' });

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Wrong password' });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET || 'secretkey',
      { expiresIn: '1h' }
    );
    res.json({ token });
  });
});

// Submit contact form
app.post('/contact', (req, res) => {
  const { name, email, phone, company, country, title, details } = req.body;
  const query = 'INSERT INTO contacts (name,email,phone,company,country,title,details) VALUES (?,?,?,?,?,?,?)';
  db.query(query, [name,email,phone,company,country,title,details], (err,result)=>{
    if(err) return res.status(500).json({ message: 'Database error', error: err });
    res.json({ message: 'Inquiry submitted!' });
  });
});

// Admin: Get all contact inquiries
app.get('/contact', verifyToken, adminOnly, (req,res)=>{
  db.query('SELECT * FROM contacts ORDER BY id DESC', (err,result)=>{
    if(err) return res.status(500).json({ message: 'Database error', error: err });
    res.json(result);
  });
});

// Admin-only route
app.get('/admin', verifyToken, adminOnly, (req, res) => {
  res.json({ message: `Welcome, Admin ${req.user.id}!` });
});

// Start backend
const PORT = 5050;
app.listen(PORT, ()=>console.log(`Server running on port ${PORT}`));
