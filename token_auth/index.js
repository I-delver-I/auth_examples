require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');
const onFinished = require('on-finished');
const uuid = require('uuid');
const fs = require('fs');

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

const SESSION_KEY = 'Authorization';
const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

class Session {
    constructor() {
        this.sessions = {};
        try {
            const data = fs.readFileSync('./sessions.json', 'utf8');
            this.sessions = JSON.parse(data.trim() || '{}');
        } catch {
            this.sessions = {};
        }
    }

    storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.sessions), 'utf-8');
    }

    set(key, value = {}) {
        this.sessions[key] = value;
        this.storeSessions();
    }

    get(key) {
        return this.sessions[key];
    }

    init() {
        const sessionId = uuid.v4();
        this.set(sessionId);
        return sessionId;
    }

    destroy(sessionId) {
        delete this.sessions[sessionId];
        this.storeSessions();
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let sessionId = req.get(SESSION_KEY);
    if (!sessionId) {
        sessionId = sessions.init();
    }
    req.sessionId = sessionId;
    req.session = sessions.get(sessionId) || {};
    onFinished(req, () => sessions.set(req.sessionId, req.session));
    next();
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'password',
            username,
            password,
            audience: `https://${AUTH0_DOMAIN}/userinfo`,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
        });

        req.session.token = response.data.access_token;

        res.json({ token: response.data.access_token, expiresIn: response.data.expires_in });
    } catch (error) {
        const errorMsg = error.response?.data || 'An unexpected error occurred';
        console.error('Auth0 Login Error:', errorMsg);
        res.status(error.response?.status || 500).json({ error: errorMsg });
    }
});

app.get('/api/profile', async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(401).json({ error: 'Access token is required' });
    }

    try {
        const userInfo = await axios.get(`https://${AUTH0_DOMAIN}/userinfo`, {
            headers: { Authorization: `Bearer ${token}` },
        });
        res.json(userInfo.data);
    } catch (error) {
        const errorMsg = error.response?.data || 'An unexpected error occurred';
        console.error('Error fetching profile:', errorMsg);
        res.status(error.response?.status || 500).json({ error: errorMsg });
    }
});

app.get('/logout', (req, res) => {
    sessions.destroy(req.sessionId);
    res.redirect('/');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => console.log(`Server is running at http://localhost:${port}`));
