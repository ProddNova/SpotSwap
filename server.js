const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'spotswap-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        ttl: 24 * 60 * 60
    }),
    cookie: {
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/spotswap', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connesso a MongoDB'))
.catch(err => console.error('❌ Errore connessione MongoDB:', err));

// Schemas
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    bio: { type: String, default: '' },
    settings: {
        notifications: { type: Boolean, default: true },
        privateProfile: { type: Boolean, default: true },
        preciseCoordinates: { type: Boolean, default: false },
        emailConfirm: { type: Boolean, default: true }
    },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const spotSchema = new mongoose.Schema({
    give: { type: String, required: true },
    want: { type: String, required: true },
    region: { type: String, required: true },
    coordinates: { type: String, required: true },
    category: { 
        type: String, 
        enum: ['industriale', 'hotel', 'villa', 'sanitario', 'militare', 'altro'],
        required: true 
    },
    description: { type: String, default: '' },
    author: { type: String, required: true },
    authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { 
        type: String, 
        enum: ['active', 'in_trade', 'completed', 'deleted'],
        default: 'active'
    },
    acquired: { type: Boolean, default: false },
    offeredForTrade: { type: Boolean, default: false },
    originalAuthor: String,
    currentOwner: String,
    acquiredDate: Date,
    originalSpotId: mongoose.Schema.Types.ObjectId,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const tradeRequestSchema = new mongoose.Schema({
    spotId: { type: mongoose.Schema.Types.ObjectId, ref: 'Spot', required: true },
    fromUser: { type: String, required: true },
    fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    toUser: { type: String, required: true },
    toUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    offeredSpots: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Spot' }],
    selectedSpotId: { type: mongoose.Schema.Types.ObjectId, ref: 'Spot' },
    status: { 
        type: String, 
        enum: ['pending', 'verifying', 'accepted', 'rejected'],
        default: 'pending'
    },
    verificationStartedAt: Date,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Spot = mongoose.model('Spot', spotSchema);
const TradeRequest = mongoose.model('TradeRequest', tradeRequestSchema);

// Middleware per autenticazione
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Autenticazione richiesta' });
    }
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Accesso admin richiesto' });
    }
    next();
};

// Routes

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Admin account hardcoded
        if (username === 'admin' && password === 'Deba420?') {
            req.session.user = {
                id: 'admin',
                username: 'admin',
                role: 'admin'
            };
            return res.json({ 
                success: true, 
                user: { username: 'admin', role: 'admin' },
                isAdmin: true
            });
        }
        
        // Test user
        if (username === 'test' && password === 'Deba420?') {
            let user = await User.findOne({ username: 'test' });
            if (!user) {
                const hashedPassword = await bcrypt.hash('Deba420?', 10);
                user = new User({
                    username: 'test',
                    password: hashedPassword,
                    bio: 'Test user account',
                    role: 'user'
                });
                await user.save();
            }
            
            req.session.user = {
                id: user._id,
                username: user.username,
                role: user.role
            };
            
            return res.json({ 
                success: true, 
                user: { 
                    username: user.username, 
                    bio: user.bio,
                    settings: user.settings
                },
                isAdmin: false
            });
        }
        
        // Regular users
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Credenziali non valide' });
        }
        
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Credenziali non valide' });
        }
        
        req.session.user = {
            id: user._id,
            username: user.username,
            role: user.role
        };
        
        res.json({ 
            success: true, 
            user: { 
                username: user.username, 
                bio: user.bio,
                settings: user.settings
            },
            isAdmin: user.role === 'admin'
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Check session
app.get('/api/session', (req, res) => {
    if (req.session.user) {
        res.json({ 
            loggedIn: true, 
            user: req.session.user,
            isAdmin: req.session.user.role === 'admin'
        });
    } else {
        res.json({ loggedIn: false });
    }
});

// Spots routes
app.get('/api/spots', requireAuth, async (req, res) => {
    try {
        const { category, search, status, userOnly } = req.query;
        let query = { status: { $ne: 'deleted' } };
        
        if (category && category !== 'all') {
            query.category = category;
        }
        
        if (search) {
            query.$or = [
                { give: { $regex: search, $options: 'i' } },
                { want: { $regex: search, $options: 'i' } },
                { region: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }
        
        if (status) {
            query.status = status;
        } else {
            query.status = 'active';
        }
        
        if (userOnly === 'true') {
            query.$or = [
                { author: req.session.user.username },
                { currentOwner: req.session.user.username }
            ];
        } else {
            query.author = { $ne: req.session.user.username };
        }
        
        const spots = await Spot.find(query)
            .sort({ createdAt: -1 })
            .lean();
        
        res.json(spots);
    } catch (error) {
        console.error('Error fetching spots:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.post('/api/spots', requireAuth, async (req, res) => {
    try {
        const spotData = {
            ...req.body,
            author: req.session.user.username,
            authorId: req.session.user.id,
            status: 'active'
        };
        
        const spot = new Spot(spotData);
        await spot.save();
        
        res.json({ success: true, spot });
    } catch (error) {
        console.error('Error creating spot:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.put('/api/spots/:id', requireAuth, async (req, res) => {
    try {
        const spot = await Spot.findById(req.params.id);
        
        if (!spot) {
            return res.status(404).json({ error: 'Spot non trovato' });
        }
        
        if (req.session.user.role !== 'admin' && 
            spot.author !== req.session.user.username && 
            spot.currentOwner !== req.session.user.username) {
            return res.status(403).json({ error: 'Non autorizzato' });
        }
        
        Object.assign(spot, req.body);
        spot.updatedAt = Date.now();
        await spot.save();
        
        res.json({ success: true, spot });
    } catch (error) {
        console.error('Error updating spot:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.delete('/api/spots/:id', requireAuth, async (req, res) => {
    try {
        const spot = await Spot.findById(req.params.id);
        
        if (!spot) {
            return res.status(404).json({ error: 'Spot non trovato' });
        }
        
        if (req.session.user.role !== 'admin' && 
            spot.author !== req.session.user.username) {
            return res.status(403).json({ error: 'Non autorizzato' });
        }
        
        spot.status = 'deleted';
        await spot.save();
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting spot:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Trade requests routes
app.get('/api/trade-requests', requireAuth, async (req, res) => {
    try {
        const requests = await TradeRequest.find({
            $or: [
                { fromUser: req.session.user.username },
                { toUser: req.session.user.username }
            ]
        })
        .populate('spotId')
        .populate('offeredSpots')
        .populate('selectedSpotId')
        .sort({ createdAt: -1 })
        .lean();
        
        res.json(requests);
    } catch (error) {
        console.error('Error fetching trade requests:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.post('/api/trade-requests', requireAuth, async (req, res) => {
    try {
        const { spotId, offeredSpots } = req.body;
        
        const spot = await Spot.findById(spotId);
        if (!spot) {
            return res.status(404).json({ error: 'Spot non trovato' });
        }
        
        const tradeRequest = new TradeRequest({
            spotId,
            fromUser: req.session.user.username,
            fromUserId: req.session.user.id,
            toUser: spot.author,
            toUserId: spot.authorId,
            offeredSpots,
            status: 'pending'
        });
        
        await tradeRequest.save();
        
        await Spot.updateMany(
            { _id: { $in: offeredSpots } },
            { $set: { offeredForTrade: true } }
        );
        
        const populatedRequest = await TradeRequest.findById(tradeRequest._id)
            .populate('spotId')
            .populate('offeredSpots');
        
        res.json({ success: true, request: populatedRequest });
    } catch (error) {
        console.error('Error creating trade request:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.put('/api/trade-requests/:id/accept', requireAuth, async (req, res) => {
    try {
        const { selectedSpotId } = req.body;
        const request = await TradeRequest.findById(req.params.id);
        
        if (!request) {
            return res.status(404).json({ error: 'Richiesta di scambio non trovata' });
        }
        
        if (request.toUser !== req.session.user.username) {
            return res.status(403).json({ error: 'Non autorizzato' });
        }
        
        request.selectedSpotId = selectedSpotId;
        request.status = 'verifying';
        request.verificationStartedAt = Date.now();
        await request.save();
        
        await Spot.findByIdAndUpdate(request.spotId, { status: 'in_trade' });
        await Spot.findByIdAndUpdate(selectedSpotId, { 
            status: 'in_trade',
            offeredForTrade: false 
        });
        
        res.json({ success: true, request });
    } catch (error) {
        console.error('Error accepting trade:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.put('/api/trade-requests/:id/complete', requireAuth, async (req, res) => {
    try {
        const request = await TradeRequest.findById(req.params.id);
        
        if (!request) {
            return res.status(404).json({ error: 'Richiesta di scambio non trovata' });
        }
        
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ error: 'Accesso admin richiesto' });
        }
        
        request.status = 'accepted';
        await request.save();
        
        await Spot.findByIdAndUpdate(request.spotId, {
            status: 'completed',
            acquired: true,
            originalAuthor: (await Spot.findById(request.spotId)).author,
            currentOwner: request.fromUser,
            acquiredDate: Date.now(),
            author: request.fromUser
        });
        
        await Spot.findByIdAndUpdate(request.selectedSpotId, {
            status: 'completed',
            acquired: true,
            originalAuthor: (await Spot.findById(request.selectedSpotId)).author,
            currentOwner: request.toUser,
            acquiredDate: Date.now(),
            author: request.toUser
        });
        
        res.json({ success: true, request });
    } catch (error) {
        console.error('Error completing trade:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.put('/api/trade-requests/:id/reject', requireAuth, async (req, res) => {
    try {
        const request = await TradeRequest.findById(req.params.id);
        
        if (!request) {
            return res.status(404).json({ error: 'Richiesta di scambio non trovata' });
        }
        
        if (req.session.user.role !== 'admin' && request.toUser !== req.session.user.username) {
            return res.status(403).json({ error: 'Non autorizzato' });
        }
        
        request.status = 'rejected';
        await request.save();
        
        await Spot.updateMany(
            { _id: { $in: request.offeredSpots } },
            { $set: { offeredForTrade: false } }
        );
        
        await Spot.findByIdAndUpdate(request.spotId, { status: 'active' });
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error rejecting trade:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// User profile routes
app.put('/api/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id);
        
        if (!user) {
            return res.status(404).json({ error: 'Utente non trovato' });
        }
        
        Object.assign(user, req.body);
        await user.save();
        
        res.json({ success: true, user });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Admin routes
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
        const [
            totalUsers,
            totalSpots,
            activeSpots,
            totalTrades,
            pendingTrades
        ] = await Promise.all([
            User.countDocuments(),
            Spot.countDocuments({ status: { $ne: 'deleted' } }),
            Spot.countDocuments({ status: 'active' }),
            TradeRequest.countDocuments(),
            TradeRequest.countDocuments({ status: 'pending' })
        ]);
        
        res.json({
            totalUsers,
            totalSpots,
            activeSpots,
            totalTrades,
            pendingTrades
        });
    } catch (error) {
        console.error('Error fetching admin stats:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password').lean();
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.get('/api/admin/trades', requireAdmin, async (req, res) => {
    try {
        const trades = await TradeRequest.find()
            .populate('spotId')
            .populate('offeredSpots')
            .populate('selectedSpotId')
            .sort({ createdAt: -1 })
            .lean();
        
        res.json(trades);
    } catch (error) {
        console.error('Error fetching trades:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Serve HTML
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server avviato su http://localhost:${PORT}`);
});