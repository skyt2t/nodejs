const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

// Initialize Express app
const app = express();
app.use(express.json());
app.use(cors());

// Create SQLite database and tables
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run(`
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    `);

    db.run(`
        CREATE TABLE todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            description TEXT,
            status TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `);
});

// Middleware for verifying JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Register endpoint
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run(INSERT INTO users (username, password) VALUES (?, ?), [username, hashedPassword], function(err) {
        if (err) return res.status(400).json({ error: 'User already exists' });
        res.status(201).json({ message: 'User registered successfully' });
    });
});

// Login endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get(SELECT * FROM users WHERE username = ?, [username], (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'User not found' });

        if (bcrypt.compareSync(password, user.password)) {
            const accessToken = jwt.sign({ username: user.username, id: user.id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
            res.json({ accessToken });
        } else {
            res.status(400).json({ error: 'Incorrect password' });
        }
    });
});

// Create To-Do item endpoint
app.post('/todos', authenticateToken, (req, res) => {
    const { description, status } = req.body;

    db.run(INSERT INTO todos (user_id, description, status) VALUES (?, ?, ?), [req.user.id, description, status], function(err) {
        if (err) return res.status(400).json({ error: 'Error creating to-do item' });
        res.status(201).json({ id: this.lastID, user_id: req.user.id, description, status });
    });
});

// Read To-Do items endpoint
app.get('/todos', authenticateToken, (req, res) => {
    db.all(SELECT * FROM todos WHERE user_id = ?, [req.user.id], (err, rows) => {
        if (err) return res.status(400).json({ error: 'Error fetching to-do items' });
        res.json(rows);
    });
});

// Update To-Do item endpoint
app.put('/todos/:id', authenticateToken, (req, res) => {
    const { description, status } = req.body;
    const { id } = req.params;

    db.run(UPDATE todos SET description = ?, status = ? WHERE id = ? AND user_id = ?, [description, status, id, req.user.id], function(err) {
        if (err) return res.status(400).json({ error: 'Error updating to-do item' });
        if (this.changes === 0) return res.status(404).json({ error: 'To-Do item not found' });
        res.json({ message: 'To-Do item updated successfully' });
    });
});

// Delete To-Do item endpoint
app.delete('/todos/:id', authenticateToken, (req, res) => {
    const { id } = req.params;

    db.run(DELETE FROM todos WHERE id = ? AND user_id = ?, [id, req.user.id], function(err) {
        if (err) return res.status(400).json({ error: 'Error deleting to-do item' });
        if (this.changes === 0) return res.status(404).json({ error: 'To-Do item not found' });
        res.json({ message: 'To-Do item deleted successfully' });
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(Server running on port ${PORT});
});