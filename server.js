const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const crypto = require('crypto');

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
    isFan: { type: Boolean, default: false },
    fanToken: { type: String },
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
    isAdminCreated: { type: Boolean, default: false },
    hasPendingTradeRequest: { type: Boolean, default: false },
    requestedBy: [{ type: String }],
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
    adminApproved: { type: Boolean, default: false },
    adminRejected: { type: Boolean, default: false },
    adminSeen: { type: Boolean, default: false },
    hiddenFromRecipient: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const fanInviteSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    createdBy: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true },
    used: { type: Boolean, default: false },
    usedBy: { type: String },
    usedAt: { type: Date }
});

const User = mongoose.model('User', userSchema);
const Spot = mongoose.model('Spot', spotSchema);
const TradeRequest = mongoose.model('TradeRequest', tradeRequestSchema);
const FanInvite = mongoose.model('FanInvite', fanInviteSchema);

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

// Register via fan token
app.post('/api/register', async (req, res) => {
    try {
        const { token, username, password } = req.body;
        
        if (!token || !username || !password) {
            return res.status(400).json({ error: 'Token, username e password richiesti' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password deve essere di almeno 6 caratteri' });
        }
        
        // Check if token exists and is valid
        const invite = await FanInvite.findOne({ 
            token, 
            used: false,
            expiresAt: { $gt: new Date() }
        });
        
        if (!invite) {
            return res.status(400).json({ error: 'Codice non valido o scaduto' });
        }
        
        // Check if username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username già in uso' });
        }
        
        // Create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            password: hashedPassword,
            bio: 'Nuovo fan di 2Lost2Find',
            role: 'user',
            isFan: true,
            fanToken: token
        });
        
        await user.save();
        
        // Mark token as used
        invite.used = true;
        invite.usedBy = username;
        invite.usedAt = new Date();
        await invite.save();
        
        res.json({ 
            success: true, 
            message: 'Registrazione completata! Ora puoi accedere.'
        });
        
    } catch (error) {
        console.error('Registration error:', error);
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
        const { category, search, status, userOnly, excludeRequested } = req.query;
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
        
        // status: per il mercato default "active", ma per userOnly vogliamo TUTTI (tranne deleted)
if (status) {
    query.status = status;
} else {
    if (userOnly === 'true') {
        // non forzare 'active'
        query.status = { $ne: 'deleted' };
    } else {
        query.status = 'active';
    }
}

if (userOnly === 'true') {
    query.$or = [
        { author: req.session.user.username },
        { currentOwner: req.session.user.username }
    ];
} else {
    query.author = { $ne: req.session.user.username };

    if (excludeRequested === 'true') {
        const userTradeRequests = await TradeRequest.find({
            fromUser: req.session.user.username,
            status: { $in: ['pending', 'verifying'] }
        });

        const requestedSpotIds = userTradeRequests.map(req => req.spotId.toString());
        query._id = { $nin: requestedSpotIds };
    }
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

// Admin create spot for any user
app.post('/api/admin/spots', requireAdmin, async (req, res) => {
    try {
        const { give, want, region, coordinates, category, description, author, authorId } = req.body;
        
        if (!give || !want || !region || !coordinates || !category || !author) {
            return res.status(400).json({ error: 'Tutti i campi sono obbligatori' });
        }
        
        // Check if author exists, if not create a dummy user
        let user = await User.findOne({ username: author });
        if (!user) {
            const randomPassword = crypto.randomBytes(8).toString('hex');
            const hashedPassword = await bcrypt.hash(randomPassword, 10);
            
            user = new User({
                username: author,
                password: hashedPassword,
                bio: 'Utente creato da admin',
                role: 'user',
                isFan: true
            });
            await user.save();
        }
        
        const spot = new Spot({
            give,
            want,
            region,
            coordinates,
            category,
            description: description || 'Spot creato da admin',
            author: author,
            authorId: user._id,
            status: 'active',
            isAdminCreated: true,
            createdAt: new Date()
        });
        
        await spot.save();
        
        res.json({ 
            success: true, 
            spot,
            message: `Spot creato per l'utente ${author}`
        });
        
    } catch (error) {
        console.error('Error creating admin spot:', error);
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
        
        // Cancella anche le richieste di scambio associate
        await TradeRequest.deleteMany({
            $or: [
                { spotId: spot._id },
                { offeredSpots: spot._id },
                { selectedSpotId: spot._id }
            ]
        });
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting spot:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Admin delete spot
app.delete('/api/admin/spots/:id', requireAdmin, async (req, res) => {
    try {
        const spot = await Spot.findById(req.params.id);
        
        if (!spot) {
            return res.status(404).json({ error: 'Spot non trovato' });
        }
        
        // Cancella lo spot
        await Spot.findByIdAndDelete(req.params.id);
        
        // Cancella anche le richieste di scambio associate
        await TradeRequest.deleteMany({
            $or: [
                { spotId: spot._id },
                { offeredSpots: spot._id },
                { selectedSpotId: spot._id }
            ]
        });
        
        res.json({ success: true, message: 'Spot eliminato con successo' });
    } catch (error) {
        console.error('Error deleting spot:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Trade requests routes
app.get('/api/trade-requests', requireAuth, async (req, res) => {
    try {
        let query = {
            $or: [
                { fromUser: req.session.user.username },
                { toUser: req.session.user.username }
            ]
        };
        
        // Se non è admin, nasconde le richieste al destinatario finché non sono approvate dall'admin
        if (req.session.user.role !== 'admin') {
            query.$or = [
                { fromUser: req.session.user.username },
                { 
                    toUser: req.session.user.username,
                    hiddenFromRecipient: false,
                    adminApproved: true
                }
            ];
        }
        
        const requests = await TradeRequest.find(query)
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
        
        // Controlla se l'utente ha già fatto una richiesta per questo spot
        const existingRequest = await TradeRequest.findOne({
            spotId: spotId,
            fromUser: req.session.user.username,
            status: { $in: ['pending', 'verifying'] }
        });
        
        if (existingRequest) {
            return res.status(400).json({ error: 'Hai già inviato una richiesta per questo spot' });
        }
        
        const tradeRequest = new TradeRequest({
            spotId,
            fromUser: req.session.user.username,
            fromUserId: req.session.user.id,
            toUser: spot.author,
            toUserId: spot.authorId,
            offeredSpots,
            status: 'pending',
            hiddenFromRecipient: true // Nascondi al destinatario finché admin non approva
        });
        
        await tradeRequest.save();
        
        // Segna lo spot come richiesto
        await Spot.findByIdAndUpdate(spotId, {
            $addToSet: { requestedBy: req.session.user.username },
            hasPendingTradeRequest: true
        });
        
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

// Admin approve trade request
app.put('/api/admin/trade-requests/:id/approve', requireAdmin, async (req, res) => {
    try {
        const request = await TradeRequest.findById(req.params.id);
        
        if (!request) {
            return res.status(404).json({ error: 'Richiesta di scambio non trovata' });
        }
        
        request.adminApproved = true;
        request.hiddenFromRecipient = false; // Ora il destinatario può vederla
        request.adminSeen = true;
        await request.save();
        
        res.json({ success: true, request });
    } catch (error) {
        console.error('Error approving trade:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Admin reject trade request
app.put('/api/admin/trade-requests/:id/reject', requireAdmin, async (req, res) => {
    try {
        const request = await TradeRequest.findById(req.params.id);
        
        if (!request) {
            return res.status(404).json({ error: 'Richiesta di scambio non trovata' });
        }
        
        request.status = 'rejected';
        request.adminRejected = true;
        request.adminSeen = true;
        await request.save();
        
        // Rimuovi lo spot dalla lista dei richiesti
        await Spot.findByIdAndUpdate(request.spotId, {
            $pull: { requestedBy: request.fromUser }
        });
        
        // Controlla se ci sono ancora richieste pendenti per lo spot
        const pendingRequests = await TradeRequest.countDocuments({
            spotId: request.spotId,
            status: { $in: ['pending', 'verifying'] }
        });
        
        if (pendingRequests === 0) {
            await Spot.findByIdAndUpdate(request.spotId, {
                hasPendingTradeRequest: false
            });
        }
        
        // Rendi nuovamente disponibili gli spot offerti
        await Spot.updateMany(
            { _id: { $in: request.offeredSpots } },
            { $set: { offeredForTrade: false } }
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error rejecting trade:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.put('/api/trade-requests/:id/accept', requireAuth, async (req, res) => {
    const sessionDb = await mongoose.startSession();

    try {
        sessionDb.startTransaction();

        const { selectedSpotId } = req.body;

        const request = await TradeRequest.findById(req.params.id).session(sessionDb);
        if (!request) {
            await sessionDb.abortTransaction();
            return res.status(404).json({ error: 'Richiesta di scambio non trovata' });
        }

        // Solo il destinatario può accettare
        if (request.toUser !== req.session.user.username) {
            await sessionDb.abortTransaction();
            return res.status(403).json({ error: 'Non autorizzato' });
        }

        // Deve essere stata approvata dall'admin (solo "sblocco visibilità")
        if (!request.adminApproved || request.adminRejected) {
            await sessionDb.abortTransaction();
            return res.status(403).json({ error: 'Richiesta non approvata dall\'admin' });
        }

        // Deve essere pending
        if (request.status !== 'pending') {
            await sessionDb.abortTransaction();
            return res.status(400).json({ error: 'Richiesta non in stato valido (non è pending)' });
        }

        if (!selectedSpotId) {
            await sessionDb.abortTransaction();
            return res.status(400).json({ error: 'selectedSpotId mancante' });
        }

        // Sicurezza: lo spot scelto deve essere tra quelli offerti
        const offeredIds = (request.offeredSpots || []).map(x => x.toString());
        if (!offeredIds.includes(selectedSpotId.toString())) {
            await sessionDb.abortTransaction();
            return res.status(400).json({ error: 'Lo spot selezionato non è tra quelli offerti' });
        }

        // Carico gli spot
        const requestedSpot = await Spot.findById(request.spotId).session(sessionDb);
        if (!requestedSpot) {
            await sessionDb.abortTransaction();
            return res.status(404).json({ error: 'Spot richiesto non trovato' });
        }

        const chosenSpot = await Spot.findById(selectedSpotId).session(sessionDb);
        if (!chosenSpot) {
            await sessionDb.abortTransaction();
            return res.status(404).json({ error: 'Spot selezionato non trovato' });
        }

        // Salvo autori originali PRIMA di cambiare author
        // Salvo gli autori originali
const requestedOriginalAuthor = requestedSpot.author; // A
const chosenOriginalAuthor = chosenSpot.author;       // B

// 1) aggiorno richiesta => accepted
request.selectedSpotId = selectedSpotId;
request.status = 'accepted';
request.updatedAt = new Date();
await request.save({ session: sessionDb });

// 2) BLOCCO gli spot originali (restano ai proprietari originali)
await Spot.findByIdAndUpdate(
  request.spotId,
  {
    status: 'completed',
    hasPendingTradeRequest: false,
    requestedBy: [],
    offeredForTrade: false
  },
  { session: sessionDb }
);

await Spot.findByIdAndUpdate(
  selectedSpotId,
  {
    status: 'completed',
    offeredForTrade: false
  },
  { session: sessionDb }
);

// 3) CREO COPIA per B (fromUser) => ottiene lo spot di A
await Spot.create([{
  give: requestedSpot.give,
  want: requestedSpot.want,
  region: requestedSpot.region,
  coordinates: requestedSpot.coordinates,
  category: requestedSpot.category,
  description: requestedSpot.description,
  author: request.fromUser,              // proprietario “visibile” della copia
  authorId: request.fromUserId,
  status: 'completed',
  acquired: true,
  originalAuthor: requestedSpot.originalAuthor || requestedOriginalAuthor,
  currentOwner: request.fromUser,
  acquiredDate: new Date(),
  originalSpotId: requestedSpot._id,
  offeredForTrade: false,
  isAdminCreated: requestedSpot.isAdminCreated || false
}], { session: sessionDb });

// 4) CREO COPIA per A (toUser) => ottiene lo spot scelto di B
await Spot.create([{
  give: chosenSpot.give,
  want: chosenSpot.want,
  region: chosenSpot.region,
  coordinates: chosenSpot.coordinates,
  category: chosenSpot.category,
  description: chosenSpot.description,
  author: request.toUser,
  authorId: request.toUserId,

  status: 'completed',
  acquired: true,
  originalAuthor: chosenSpot.originalAuthor || chosenOriginalAuthor,
  currentOwner: request.toUser,
  acquiredDate: new Date(),
  originalSpotId: chosenSpot._id,
  offeredForTrade: false,
  isAdminCreated: chosenSpot.isAdminCreated || false
}], { session: sessionDb });

// 5) rendo liberi gli altri spot offerti non scelti
const offeredIds = (request.offeredSpots || []).map(x => x.toString());
const otherOffered = offeredIds.filter(id => id !== selectedSpotId.toString());

if (otherOffered.length > 0) {
  await Spot.updateMany(
    { _id: { $in: otherOffered } },
    { $set: { offeredForTrade: false, status: 'active' } },
    { session: sessionDb }
  );
}


        // 5) rifiuto automaticamente le altre richieste pendenti sullo stesso spot richiesto
        await TradeRequest.updateMany(
            {
                _id: { $ne: request._id },
                spotId: request.spotId,
                status: { $in: ['pending', 'verifying'] } // anche se esiste legacy
            },
            {
                $set: {
                    status: 'rejected',
                    adminRejected: true,
                    adminSeen: true,
                    updatedAt: new Date()
                }
            },
            { session: sessionDb }
        );

        await sessionDb.commitTransaction();
        return res.json({ success: true });

    } catch (error) {
        console.error('Error accepting trade (instant complete):', error);
        try { await sessionDb.abortTransaction(); } catch (e) {}
        return res.status(500).json({ error: 'Errore interno del server' });
    } finally {
        sessionDb.endSession();
    }
});


app.put('/api/trade-requests/:id/complete', requireAdmin, async (req, res) => {
    try {
        const request = await TradeRequest.findById(req.params.id);
        
        if (!request) {
            return res.status(404).json({ error: 'Richiesta di scambio non trovata' });
        }
        
        request.status = 'accepted';
        await request.save();
        
        // Trasferisci lo spot richiesto al mittente
        await Spot.findByIdAndUpdate(request.spotId, {
            status: 'completed',
            acquired: true,
            originalAuthor: (await Spot.findById(request.spotId)).author,
            currentOwner: request.fromUser,
            acquiredDate: Date.now(),
            author: request.fromUser,
            hasPendingTradeRequest: false,
            requestedBy: []
        });
        
        // Trasferisci lo spot selezionato al destinatario
        await Spot.findByIdAndUpdate(request.selectedSpotId, {
            status: 'completed',
            acquired: true,
            originalAuthor: (await Spot.findById(request.selectedSpotId)).author,
            currentOwner: request.toUser,
            acquiredDate: Date.now(),
            author: request.toUser,
            offeredForTrade: false
        });
        
        // Aggiorna tutti gli altri spot offerti a non più in offerta
        await Spot.updateMany(
            { _id: { $in: request.offeredSpots, $ne: request.selectedSpotId } },
            { $set: { offeredForTrade: false } }
        );
        
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
        
        // Rimuovi lo spot dalla lista dei richiesti
        await Spot.findByIdAndUpdate(request.spotId, {
            $pull: { requestedBy: request.fromUser }
        });
        
        // Controlla se ci sono ancora richieste pendenti per lo spot
        const pendingRequests = await TradeRequest.countDocuments({
            spotId: request.spotId,
            status: { $in: ['pending', 'verifying'] }
        });
        
        if (pendingRequests === 0) {
            await Spot.findByIdAndUpdate(request.spotId, {
                hasPendingTradeRequest: false
            });
        }
        
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
            pendingTrades,
            fanUsers,
            activeInvites,
            pendingAdminApprovalTrades
        ] = await Promise.all([
            User.countDocuments(),
            Spot.countDocuments({ status: { $ne: 'deleted' } }),
            Spot.countDocuments({ status: 'active' }),
            TradeRequest.countDocuments(),
            TradeRequest.countDocuments({ status: 'pending' }),
            User.countDocuments({ isFan: true }),
            FanInvite.countDocuments({ used: false, expiresAt: { $gt: new Date() } }),
            TradeRequest.countDocuments({ adminApproved: false, adminRejected: false })
        ]);
        
        res.json({
            totalUsers,
            totalSpots,
            activeSpots,
            totalTrades,
            pendingTrades,
            fanUsers,
            activeInvites,
            pendingAdminApprovalTrades
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

app.get('/api/admin/spots', requireAdmin, async (req, res) => {
    try {
        const { status, search } = req.query;
        let query = { status: { $ne: 'deleted' } };
        
        if (status && status !== 'all') {
            query.status = status;
        }
        
        if (search) {
            query.$or = [
                { give: { $regex: search, $options: 'i' } },
                { want: { $regex: search, $options: 'i' } },
                { region: { $regex: search, $options: 'i' } },
                { author: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }
        
        const spots = await Spot.find(query)
            .sort({ createdAt: -1 })
            .lean();
        
        res.json(spots);
    } catch (error) {
        console.error('Error fetching admin spots:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Fan invite routes - now generates codes instead of URLs
app.post('/api/admin/invites', requireAdmin, async (req, res) => {
    try {
        const { hoursValid } = req.body;
        const expiresHours = parseInt(hoursValid) || 24;
        
        // Generate unique token (12 characters, formatted as XXXX-XXXX-XXXX)
        const token = crypto.randomBytes(6).toString('hex').toUpperCase(); // 12 characters
        
        const invite = new FanInvite({
            token,
            createdBy: req.session.user.username,
            expiresAt: new Date(Date.now() + expiresHours * 60 * 60 * 1000)
        });
        
        await invite.save();
        
        res.json({
            success: true,
            invite: {
                token,
                createdBy: invite.createdBy,
                createdAt: invite.createdAt,
                expiresAt: invite.expiresAt
            }
        });
        
    } catch (error) {
        console.error('Error creating invite:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.get('/api/admin/invites', requireAdmin, async (req, res) => {
    try {
        const invites = await FanInvite.find()
            .sort({ createdAt: -1 })
            .lean();
        
        res.json(invites);
    } catch (error) {
        console.error('Error fetching invites:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.delete('/api/admin/invites/:id', requireAdmin, async (req, res) => {
    try {
        await FanInvite.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting invite:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Check token validity
app.get('/api/check-token/:token', async (req, res) => {
    try {
        const { token } = req.params;
        
        const invite = await FanInvite.findOne({ 
            token, 
            used: false,
            expiresAt: { $gt: new Date() }
        });
        
        if (!invite) {
            return res.json({ valid: false, message: 'Codice non valido o scaduto' });
        }
        
        res.json({ 
            valid: true, 
            expiresAt: invite.expiresAt,
            createdBy: invite.createdBy
        });
        
    } catch (error) {
        console.error('Error checking token:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Serve HTML
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Clean up expired invites every hour
setInterval(async () => {
    try {
        const result = await FanInvite.deleteMany({
            expiresAt: { $lt: new Date() },
            used: false
        });
        if (result.deletedCount > 0) {
            console.log(`Puliti ${result.deletedCount} codici scaduti`);
        }
    } catch (error) {
        console.error('Error cleaning expired invites:', error);
    }
}, 60 * 60 * 1000); // Every hour

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server avviato su http://localhost:${PORT}`);
});
