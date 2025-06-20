
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const session = require('express-session');
const { default: makeWASocket, DisconnectReason, useMultiFileAuthState, delay } = require('@whiskeysockets/baileys');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = 3000;

// Hardcoded users
const users = {
    'admin': { password: 'admin123', phone: '9209778319', isAdmin: true },
    'user1': { password: '9588586256', phone: '9876543210', isAdmin: false },
    'user2': { password: 'test123', phone: '9123456789', isAdmin: false }
};

// Store WhatsApp connections per user
const userConnections = new Map();

// Middleware
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Session middleware
app.use(session({
    secret: 'whatsapp-joiner-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.username) {
        return next();
    }
    return res.redirect('/login');
}

// Create sessions directory
if (!fs.existsSync('./sessions')) {
    fs.mkdirSync('./sessions', { recursive: true });
}

// Routes
app.get('/', (req, res) => {
    if (req.session && req.session.username) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    if (req.session && req.session.username) {
        return res.redirect('/dashboard');
    }
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if (users[username] && users[username].password === password) {
        req.session.username = username;
        req.session.isAdmin = users[username].isAdmin;
        req.session.phone = users[username].phone;
        return res.redirect('/dashboard');
    }
    
    res.render('login', { error: 'Invalid username or password' });
});

app.get('/dashboard', requireAuth, (req, res) => {
    const userConn = userConnections.get(req.session.username);
    res.render('dashboard', { 
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        isConnected: userConn ? userConn.isConnected : false,
        currentQR: userConn ? userConn.currentQR : null
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

app.post('/disconnect', requireAuth, async (req, res) => {
    const username = req.session.username;
    const userConn = userConnections.get(username);
    
    try {
        if (userConn && userConn.sock) {
            await userConn.sock.logout();
            userConn.sock = null;
        }
        
        // Update connection state
        if (userConn) {
            userConn.isConnected = false;
            userConn.currentQR = null;
        }
        
        // Clear auth files for this user
        const authPath = `./sessions/${username}/auth_info_multi`;
        if (fs.existsSync(authPath)) {
            fs.rmSync(authPath, { recursive: true, force: true });
        }
        
        // Emit to user's socket room
        io.to(`user-${username}`).emit('connectionStatus', { connected: false });
        io.to(`user-${username}`).emit('disconnected', { message: 'Successfully disconnected from WhatsApp' });
        
        res.json({ success: true, message: 'Successfully disconnected from WhatsApp' });
    } catch (error) {
        console.error('Disconnect error:', error);
        res.json({ success: false, message: 'Error during disconnect: ' + error.message });
    }
});

app.post('/join-groups', requireAuth, async (req, res) => {
    const username = req.session.username;
    const userConn = userConnections.get(username);
    
    if (!userConn || !userConn.isConnected || !userConn.sock) {
        return res.json({ success: false, message: 'WhatsApp not connected' });
    }

    const { links } = req.body;
    if (!links || links.trim() === '') {
        return res.json({ success: false, message: 'No links provided' });
    }

    const inviteLinks = links.split(/[,\n]/).map(link => link.trim()).filter(Boolean);
    const results = [];

    for (let i = 0; i < inviteLinks.length; i++) {
        const link = inviteLinks[i];
        const code = extractInviteCode(link);
        
        if (!code) {
            results.push({
                link: link,
                success: false,
                message: 'Invalid invite link format'
            });
            continue;
        }

        try {
            const result = await userConn.sock.groupAcceptInvite(code);
            results.push({
                link: link,
                success: true,
                message: `Successfully joined group: ${result}`,
                groupId: result
            });
            
            io.to(`user-${username}`).emit('joinResult', {
                index: i + 1,
                total: inviteLinks.length,
                link: link,
                success: true,
                message: `Successfully joined group: ${result}`
            });
        } catch (error) {
            results.push({
                link: link,
                success: false,
                message: `Failed to join: ${error.message}`
            });
            
            io.to(`user-${username}`).emit('joinResult', {
                index: i + 1,
                total: inviteLinks.length,
                link: link,
                success: false,
                message: `Failed to join: ${error.message}`
            });
        }

        if (i < inviteLinks.length - 1) {
            io.to(`user-${username}`).emit('waiting', { seconds: 8 });
            await delay(8000);
        }
    }

    res.json({ success: true, results: results });
});

// Helper function
function extractInviteCode(link) {
    const match = link.match(/https:\/\/chat\.whatsapp\.com\/([a-zA-Z0-9]+)/);
    return match ? match[1] : null;
}

// WhatsApp connection function for specific user
async function connectToWhatsApp(username) {
    console.log(`🚀 Starting WhatsApp connection for user: ${username}`);
    
    const authPath = `./sessions/${username}/auth_info_multi`;
    
    // Create user session directory
    if (!fs.existsSync(`./sessions/${username}`)) {
        fs.mkdirSync(`./sessions/${username}`, { recursive: true });
    }
    
    if (!fs.existsSync(authPath)) {
        fs.mkdirSync(authPath, { recursive: true });
    }
    
    const { state, saveCreds } = await useMultiFileAuthState(authPath);
    
    const sock = makeWASocket({
        auth: state,
        printQRInTerminal: false
    });

    // Initialize or get user connection
    let userConn = userConnections.get(username);
    if (!userConn) {
        userConn = {
            sock: null,
            isConnected: false,
            currentQR: null
        };
        userConnections.set(username, userConn);
    }
    
    userConn.sock = sock;

    sock.ev.on('connection.update', async (update) => {
        const { connection, lastDisconnect, qr } = update;
        
        if (qr) {
            console.log(`📱 QR Code generated for user: ${username}`);
            try {
                userConn.currentQR = await QRCode.toDataURL(qr);
                io.to(`user-${username}`).emit('qrCode', userConn.currentQR);
            } catch (err) {
                console.error('Error generating QR code:', err);
            }
        }
        
        if (connection === 'close') {
            const shouldReconnect = (lastDisconnect?.error)?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log(`❌ Connection closed for user ${username} due to`, lastDisconnect?.error, ', reconnecting:', shouldReconnect);
            
            userConn.isConnected = false;
            userConn.currentQR = null;
            io.to(`user-${username}`).emit('connectionStatus', { connected: false });
            
            if (shouldReconnect) {
                setTimeout(() => connectToWhatsApp(username), 5000);
            }
        } else if (connection === 'open') {
            console.log(`✅ Connected to WhatsApp successfully for user: ${username}!`);
            userConn.isConnected = true;
            userConn.currentQR = null;
            io.to(`user-${username}`).emit('connectionStatus', { connected: true });
        }
    });

    sock.ev.on('creds.update', saveCreds);
}

// Socket.IO connection
io.on('connection', (socket) => {
    console.log('👤 User connected');
    
    socket.on('joinUserRoom', (username) => {
        socket.join(`user-${username}`);
        console.log(`User ${username} joined their room`);
        
        // Send current status to user
        const userConn = userConnections.get(username);
        if (userConn) {
            socket.emit('connectionStatus', { connected: userConn.isConnected });
            if (userConn.currentQR) {
                socket.emit('qrCode', userConn.currentQR);
            }
        } else {
            socket.emit('connectionStatus', { connected: false });
        }
        
        // Start WhatsApp connection for this user if not already connected
        if (!userConn || !userConn.isConnected) {
            connectToWhatsApp(username);
        }
    });
    
    socket.on('disconnect', () => {
        console.log('👤 User disconnected');
    });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🌐 Server running on http://0.0.0.0:${PORT}`);
});

// Handle process termination
process.on('SIGINT', () => {
    console.log('\n\n👋 Server shutting down...');
    userConnections.forEach((userConn) => {
        if (userConn.sock) {
            userConn.sock.logout();
        }
    });
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n\n👋 Server terminated...');
    userConnections.forEach((userConn) => {
        if (userConn.sock) {
            userConn.sock.logout();
        }
    });
    process.exit(0);
});
