const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const util = require('util');

const app = express();
const PORT = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY || 'default_secret_key';

// MySQL Connection
const db = mysql.createConnection({
  host: '110.4.45.165',
  port: '3306',
  user: 'wp_bhbzr',
  password: '@KamellaTech123',
  database: 'wp_yxtfy',
});

const queryAsync = util.promisify(db.query).bind(db);

db.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        process.exit(1);
    }
    console.log('Connected to MySQL database');
});

app.use(express.json());

// Helper functions for password hashing and verification
function hashPassword(password) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16).toString('hex');
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(salt + ":" + derivedKey.toString('hex'));
        });
    });
}

function verifyPassword(password, hash) {
    return new Promise((resolve, reject) => {
        const [salt, key] = hash.split(":");
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(key === derivedKey.toString('hex'));
        });
    });
}

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await hashPassword(password);
        const user = { username, password: hashedPassword };
        await queryAsync('INSERT INTO users SET ?', user);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).json({ error: 'Error registering user' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const results = await queryAsync('SELECT * FROM users WHERE username = ?', [username]);
        if (results.length === 0) {
            res.status(401).json({ error: 'Invalid username or password' });
            return;
        }
        const user = results[0];
        const match = await verifyPassword(password, user.password);
        if (match) {
            const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '1h' });
            res.json({ token });
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).json({ error: 'Error logging in' });
    }
});

// Middleware to verify token
function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearerToken = bearerHeader.split(' ')[1];
        jwt.verify(bearerToken, secretKey, (err, authData) => {
            if (err) {
                res.status(403).json({ error: 'Token verification failed' });
                return;
            }
            req.authData = authData;
            next();
        });
    } else {
        res.status(403).json({ error: 'Bearer token is required' });
    }
}

// Reset Password endpoint
app.post('/api/reset-password', async (req, res) => {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) {
        return res.status(400).json({ error: 'Username and newPassword are required' });
    }
    try {
        const hashedPassword = await hashPassword(newPassword);
        const result = await queryAsync('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username]);
        if (result.affectedRows === 0) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        res.json({ message: 'Password reset successfully' });
    } catch (err) {
        console.error('Error resetting password:', err);
        res.status(500).json({ error: 'Error resetting password' });
    }
});

app.get('/', (req, res) => {
    res.redirect('https://staging-mycor.com.my/');
});

app.get('/api/users', verifyToken, async (req, res) => {
    try {
        const results = await queryAsync('SELECT * FROM users');
        res.json(results);
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ error: 'Error fetching users' });
    }
});

// Fetching user latest certification info
app.post('/api/getUserLatestCertInfo', verifyToken, async (req, res) => {
    const identifiers = req.body;

    if (!Array.isArray(identifiers) || identifiers.length === 0) {
        return res.status(400).json({ error: 'Request body must be an array of identifiers (email or passport ID).' });
    }

    let responses = [];
    let processedPassports = new Set();  // To keep track of processed passports

    for (let identifier of identifiers) {
        const sql = `
            SELECT 
                XU.display_name AS name, 
                XM.meta_value AS no_passport, 
                CC.id AS cert_id, 
                CC.completion_date
            FROM xxv0ON_users XU
            INNER JOIN xxv0ON_usermeta XM ON XM.user_id = XU.ID
            INNER JOIN enrollment E on E.user_id = XU.ID
            INNER JOIN complete_certificate CC ON CC.enroll_id = E.id
            WHERE 
                (XU.user_email = ? OR XM.meta_value = ?) AND
                XM.meta_key = 'passport'
            ORDER BY CC.completion_date DESC
            LIMIT 1`;

        try {
            const result = await queryAsync(sql, [identifier, identifier]);
            if (result.length > 0) {
                const passport = result[0].no_passport;
                const date = new Date(result[0].completion_date);
                const formattedDate = `${date.getFullYear()}-${('0' + (date.getMonth() + 1)).slice(-2)}-${('0' + date.getDate()).slice(-2)} ${('0' + date.getHours()).slice(-2)}:${('0' + date.getMinutes()).slice(-2)}`;

                if (!processedPassports.has(passport)) {
                    processedPassports.add(passport);
                    responses.push({
                        identifier: identifier,
                        name: result[0].name,
                        no_passport: passport,
                        cert_id: result[0].cert_id,
                        completion_date: formattedDate
                    });
                } else {
                    // If this passport has already been processed, skip adding to responses if identifier is not an email
                    if (identifier.includes("@")) {
                        responses.push({
                            identifier: identifier,
                            message: 'This passport information has been provided under another identifier.'
                        });
                    }
                }
            } else {
                responses.push({
                    identifier: identifier,
                    message: 'No record found'
                });
            }
        } catch (err) {
            console.error('Query error for identifier', identifier, ':', err.message);
            responses.push({
                identifier: identifier,
                message: 'Error during query execution: ' + err.message
            });
        }
    }

    res.json(responses);
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
