const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const crypto = require('crypto');
const csv = require('csv-parser');
const multer = require('multer');
const { Readable } = require('stream');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Configure multer for file upload
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
// Aggiungi dopo le altre costanti
const italianProvinces = {
  'Abruzzo': ['Chieti', 'L\'Aquila', 'Pescara', 'Teramo'],
  'Basilicata': ['Matera', 'Potenza'],
  'Calabria': ['Catanzaro', 'Cosenza', 'Crotone', 'Reggio Calabria', 'Vibo Valentia'],
  'Campania': ['Avellino', 'Benevento', 'Caserta', 'Napoli', 'Salerno'],
  'Emilia-Romagna': ['Bologna', 'Ferrara', 'Forlì-Cesena', 'Modena', 'Parma', 'Piacenza', 'Ravenna', 'Reggio Emilia', 'Rimini'],
  'Friuli-Venezia Giulia': ['Gorizia', 'Pordenone', 'Trieste', 'Udine'],
  'Lazio': ['Frosinone', 'Latina', 'Rieti', 'Roma', 'Viterbo'],
  'Liguria': ['Genova', 'Imperia', 'La Spezia', 'Savona'],
  'Lombardia': ['Bergamo', 'Brescia', 'Como', 'Cremona', 'Lecco', 'Lodi', 'Mantova', 'Milano', 'Monza e Brianza', 'Pavia', 'Sondrio', 'Varese'],
  'Marche': ['Ancona', 'Ascoli Piceno', 'Fermo', 'Macerata', 'Pesaro e Urbino'],
  'Molise': ['Campobasso', 'Isernia'],
  'Piemonte': ['Alessandria', 'Asti', 'Biella', 'Cuneo', 'Novara', 'Torino', 'Verbano-Cusio-Ossola', 'Vercelli'],
  'Puglia': ['Bari', 'Barletta-Andria-Trani', 'Brindisi', 'Foggia', 'Lecce', 'Taranto'],
  'Sardegna': ['Cagliari', 'Nuoro', 'Oristano', 'Sassari', 'Sud Sardegna'],
  'Sicilia': ['Agrigento', 'Caltanissetta', 'Catania', 'Enna', 'Messina', 'Palermo', 'Ragusa', 'Siracusa', 'Trapani'],
  'Toscana': ['Arezzo', 'Firenze', 'Grosseto', 'Livorno', 'Lucca', 'Massa-Carrara', 'Pisa', 'Pistoia', 'Prato', 'Siena'],
  'Trentino-Alto Adige': ['Bolzano', 'Trento'],
  'Umbria': ['Perugia', 'Terni'],
  'Valle d\'Aosta': ['Aosta'],
  'Veneto': ['Belluno', 'Padova', 'Rovigo', 'Treviso', 'Venezia', 'Verona', 'Vicenza']
};
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
    isContentCreator: { type: Boolean, default: false }, // ← AGGIUNGI QUESTA RIGA
    isFan: { type: Boolean, default: false },
    fanToken: { type: String },
    createdAt: { type: Date, default: Date.now }
});

const spotSchema = new mongoose.Schema({
    give: { type: String, required: true },
    want: { type: String, required: true },
    region: { type: String, required: true },
    province: { type: String, required: true },
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
    isPrivate: { type: Boolean, default: false },
    acquired: { type: Boolean, default: false },
    offeredForTrade: { type: Boolean, default: false },
    originalAuthor: String,
    currentOwner: String,
    acquiredDate: Date,
    originalSpotId: { type: mongoose.Schema.Types.ObjectId, ref: 'Spot' },
    isAdminCreated: { type: Boolean, default: false },
    hasPendingTradeRequest: { type: Boolean, default: false },
    requestedBy: [{ type: String }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
// Dopo aver definito lo schema, aggiungi questo middleware
spotSchema.pre('save', function(next) {
    if (!this.province) {
        // Se la provincia non è specificata, usa un valore di default
        // o calcolala dalla regione
        this.province = 'Non specificata';
    }
    next();
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
    expiresAt: { type: Date },
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
        
        // Check if token exists and is valid (not used)
        const invite = await FanInvite.findOne({ 
            token, 
            used: false
        });
        
        if (!invite) {
            return res.status(400).json({ error: 'Codice non valido o già utilizzato' });
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
        
        if (status) {
            query.status = status;
        } else {
            if (userOnly === 'true') {
                // For user's spots, show all statuses except deleted
                query.status = { $ne: 'deleted' };
            } else {
                // For market, only show active spots
                query.status = 'active';
            }
        }

        if (userOnly === 'true') {
            // Show both published and acquired spots for the user
            query.$or = [
                { author: req.session.user.username, originalSpotId: { $exists: false } }, // Original published spots
                { currentOwner: req.session.user.username, acquired: true } // Acquired spots
            ];
        } else {
          // Exclude user's own spots from market
          query.author = { $ne: req.session.user.username };
          query.isPrivate = { $ne: true };
    if (excludeRequested === 'true') {
      // Trova gli spot per cui l'utente ha già inviato richieste PENDENTI
      const userPendingRequests = await TradeRequest.find({
        fromUser: req.session.user.username,
        status: { $in: ['pending', 'verifying'] }
      });
    
      // Trova gli spot che l'utente ha già SCAMBIATO (accepted) come fromUser
      const userAcceptedRequestsAsFromUser = await TradeRequest.find({
        fromUser: req.session.user.username,
        status: 'accepted'
      }).populate('spotId');
    
      // Trova gli spot che l'utente ha già SCAMBIATO (accepted) come toUser
      const userAcceptedRequestsAsToUser = await TradeRequest.find({
        toUser: req.session.user.username,
        status: 'accepted'
      }).populate('selectedSpotId');
    
      // Combina tutti gli spot ID da escludere
      const excludedSpotIds = [
        ...userPendingRequests.map(req => req.spotId.toString()),
        ...userAcceptedRequestsAsFromUser.map(req => req.spotId?._id?.toString()).filter(Boolean),
        ...userAcceptedRequestsAsToUser.map(req => req.selectedSpotId?._id?.toString()).filter(Boolean)
      ];
    // Helper per verificare se l'utente possiede già uno spot
    async function userOwnsSpot(userId, spotId) {
      const spot = await Spot.findById(spotId);
      if (!spot) return false;
      
      // Controlla se l'utente è il proprietario corrente
      if (spot.currentOwner === userId || spot.author === userId) {
        return true;
      }
      
      // Controlla se l'utente ha acquisito questo spot tramite scambio
      const acquiredCopy = await Spot.findOne({
        originalSpotId: spotId,
        currentOwner: userId,
        acquired: true
      });
      
      return !!acquiredCopy;
    }
      // Rimuovi duplicati
      const uniqueExcludedSpotIds = [...new Set(excludedSpotIds.filter(id => id))];
    
      // Aggiungi anche gli spot che l'utente ha acquisito
      const acquiredSpots = await Spot.find({
        $or: [
          { currentOwner: req.session.user.username, acquired: true },
          { author: req.session.user.username, originalSpotId: { $exists: false } }
        ]
      });
    
      const acquiredOriginalSpotIds = acquiredSpots
        .map(spot => spot.originalSpotId?.toString() || spot._id.toString())
        .filter(id => id);
    
      // Combina tutte le esclusioni
      const allExcludedIds = [...uniqueExcludedSpotIds, ...acquiredOriginalSpotIds];
      
      if (allExcludedIds.length > 0) {
        query._id = { $nin: allExcludedIds };
      }
    }
          
          // In market, only show original spots (not copies)
          query.originalSpotId = { $exists: false };
          
          // Mostra solo spot attivi
          query.status = 'active';
        }
        
        const spots = await Spot.find(query)
                    .sort({ createdAt: -1 })
                    .lean();
        
        // Aggiungi informazioni content creator e livello utente
        const spotsWithUserInfo = await Promise.all(spots.map(async (spot) => {
            const author = await User.findOne({ username: spot.author }).lean();
            const authorSpotCount = await Spot.countDocuments({ 
                author: spot.author, 
                status: { $ne: 'deleted' },
                originalSpotId: { $exists: false }
            });
            
            return {
                ...spot,
                authorIsContentCreator: author?.isContentCreator || false,
                authorSpotCount: authorSpotCount
            };
        }));
        
        res.json(spotsWithUserInfo);
    } catch (error) {
        console.error('Error fetching spots:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.post('/api/spots', requireAuth, async (req, res) => {
    try {
        const spotData = {
            ...req.body,
            province: req.body.province,
            author: req.session.user.username,
            authorId: req.session.user.id,
            status: 'active',
            isPrivate: req.body.isPrivate === true || req.body.isPrivate === 'true' // Converti in booleano
        };
        
        // Validazione: controlla che la provincia sia valida per la regione
        if (spotData.province) {
            const validProvinces = italianProvinces[spotData.region] || [];
            if (!validProvinces.includes(spotData.province)) {
                return res.status(400).json({ error: 'Provincia non valida per la regione selezionata' });
            }
        }
        
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

// Admin import spots from CSV
app.post('/api/admin/spots/import', requireAdmin, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Nessun file caricato' });
        }
        
        const fileBuffer = req.file.buffer.toString();
        const results = [];
        
        const parser = csv({ headers: false });
        const stream = Readable.from(fileBuffer);
        
        let errorOccurred = false;
        
        stream.pipe(parser)
            .on('data', (data) => {
                results.push(data);
            })
            .on('error', (error) => {
                console.error('Error parsing CSV:', error);
                if (!errorOccurred) {
                    errorOccurred = true;
                    res.status(500).json({ error: 'Errore nel parsing del CSV' });
                }
            })
            .on('end', async () => {
                if (errorOccurred) return;
                
                try {
                    // Ora results è un array di array
                    // La prima riga (indice 0) è l'intestazione, la saltiamo
                    const spots = [];
                    let errors = [];
                    
                    for (let i = 1; i < results.length; i++) {
                        const row = results[i];
                        let username, give, want, region, category, coordinates, description;
                        
                        if (row.length === 8) {
                            // Nuovo formato: username, give, want, region, category, lat, lng, description
                            [username, give, want, region, category, lat, lng, description] = row.map(field => field.trim());
                            coordinates = `${lat}, ${lng}`;
                        } else if (row.length === 7) {
                            // Vecchio formato: username, give, want, region, category, coordinates, description
                            [username, give, want, region, category, coordinates, description] = row.map(field => field.trim());
                        } else {
                            errors.push(`Riga ${i}: numero di campi non valido (${row.length})`);
                            continue;
                        }
                        
                        // Validazione campi obbligatori
                        if (!username || !give || !want || !region || !category) {
                            errors.push(`Riga ${i}: campi obbligatori mancanti`);
                            continue;
                        }
                        
                        // Controllo o creazione utente
                        let user = await User.findOne({ username });
                        if (!user) {
                            const randomPassword = crypto.randomBytes(8).toString('hex');
                            const hashedPassword = await bcrypt.hash(randomPassword, 10);
                            
                            user = new User({
                                username,
                                password: hashedPassword,
                                bio: 'Utente creato da import CSV',
                                role: 'user',
                                isFan: true
                            });
                            await user.save();
                        }
                        
                        // Genera coordinate se non fornite
                        let finalCoordinates = coordinates;
                        if (!finalCoordinates || finalCoordinates.split(',').length < 2) {
                            const regionCoordinates = {
                                'Abruzzo': { lat: 42.3506, lng: 13.3995 },
                                'Basilicata': { lat: 40.6390, lng: 15.8057 },
                                'Calabria': { lat: 38.9101, lng: 16.5875 },
                                'Campania': { lat: 40.8359, lng: 14.2488 },
                                'Emilia-Romagna': { lat: 44.4949, lng: 11.3426 },
                                'Friuli-Venezia Giulia': { lat: 45.6371, lng: 13.8038 },
                                'Lazio': { lat: 41.8719, lng: 12.5674 },
                                'Liguria': { lat: 44.4056, lng: 8.9463 },
                                'Lombardia': { lat: 45.4642, lng: 9.1900 },
                                'Marche': { lat: 43.6158, lng: 13.5189 },
                                'Molise': { lat: 41.5616, lng: 14.6682 },
                                'Piemonte': { lat: 45.0703, lng: 7.6869 },
                                'Puglia': { lat: 40.9476, lng: 17.1047 },
                                'Sardegna': { lat: 39.2238, lng: 9.1217 },
                                'Sicilia': { lat: 38.1157, lng: 13.3615 },
                                'Toscana': { lat: 43.7696, lng: 11.2558 },
                                'Trentino-Alto Adige': { lat: 46.4983, lng: 11.3548 },
                                'Umbria': { lat: 42.9380, lng: 12.6144 },
                                "Valle d'Aosta": { lat: 45.7376, lng: 7.3207 },
                                'Veneto': { lat: 45.4408, lng: 12.3155 }
                            };
                            
                            const baseCoords = regionCoordinates[region] || { lat: 41.8719, lng: 12.5674 };
                            const lat = baseCoords.lat + (Math.random() - 0.5) * 0.5;
                            const lng = baseCoords.lng + (Math.random() - 0.5) * 0.5;
                            finalCoordinates = `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
                        }
                        
                        // Mappatura categoria
                        let normalizedCategory = category.toLowerCase();
                        const categoryMapping = {
                            'residenziale': 'villa',
                            'industriale': 'industriale',
                            'alberghiero': 'hotel',
                            'ospedaliero': 'sanitario',
                            'militare': 'militare',
                            'ferroviario': 'altro',
                            'rurale': 'altro',
                            'religioso': 'altro',
                            'commerciale': 'altro',
                            'aereoportuale': 'altro',
                            'culturale': 'altro',
                            'termale': 'altro',
                            'turistico': 'altro',
                            'istituzionale': 'altro',
                            'borgo': 'altro',
                            'castello': 'altro'
                        };
                        
                        if (categoryMapping[normalizedCategory]) {
                            normalizedCategory = categoryMapping[normalizedCategory];
                        } else if (!['industriale', 'hotel', 'villa', 'sanitario', 'militare', 'altro'].includes(normalizedCategory)) {
                            normalizedCategory = 'altro';
                        }
                        
                        spots.push({
                            give,
                            want,
                            region,
                            coordinates: finalCoordinates,
                            category: normalizedCategory,
                            description: description || `Spot importato per ${username}`,
                            author: username,
                            authorId: user._id,
                            status: 'active',
                            isAdminCreated: true,
                            createdAt: new Date(),
                            updatedAt: new Date()
                        });
                    }
                    
                    if (spots.length === 0) {
                        return res.status(400).json({ error: 'Nessuno spot valido trovato nel file' });
                    }
                    
                    // Inserisci tutti gli spot
                    const insertedSpots = await Spot.insertMany(spots);
                    
                    res.json({
                        success: true,
                        imported: insertedSpots.length,
                        errors: errors.length > 0 ? errors : null,
                        message: `Importati ${insertedSpots.length} spot con successo`
                    });
                } catch (error) {
                    console.error('Error in import process:', error);
                    res.status(500).json({ error: 'Errore interno del server' });
                }
            });
    } catch (error) {
        console.error('Error importing spots:', error);
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
            hasPendingTradeRequest: false,
            $pull: { requestedBy: request.fromUser },
            offeredForTrade: false
          },
          { session: sessionDb }
        );

        await Spot.findByIdAndUpdate(
          selectedSpotId,
          {
            offeredForTrade: false,
            status: 'active'  // Mantieni attivo invece di completed
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
          author: request.fromUser,              // proprietario "visibile" della copia
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
        const otherOffered = offeredIds.filter(id => id !== selectedSpotId.toString());

        if (otherOffered.length > 0) {
          await Spot.updateMany(
            { _id: { $in: otherOffered } },
            { $set: { offeredForTrade: false, status: 'active' } },
            { session: sessionDb }
          );
        }

        // 6) rifiuto automaticamente le altre richieste pendenti sullo stesso spot richiesto
        await TradeRequest.updateMany(
            {
                _id: { $ne: request._id },
                spotId: request.spotId,
                status: { $in: ['pending', 'verifying'] }
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
            Spot.countDocuments({ status: 'active', originalSpotId: { $exists: false } }),
            TradeRequest.countDocuments(),
            TradeRequest.countDocuments({ status: 'pending' }),
            User.countDocuments({ isFan: true }),
            FanInvite.countDocuments({ used: false }),
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

// Admin user management
app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
    try {
        const { username, bio, role, password } = req.body;
        
        if (!username) {
            return res.status(400).json({ error: 'Username richiesto' });
        }
        
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'Utente non trovato' });
        }
        
        // Check if username already exists (excluding current user)
        if (username !== user.username) {
            const existingUser = await User.findOne({ username });
            if (existingUser) {
                return res.status(400).json({ error: 'Username già in uso' });
            }
        }
        
        user.username = username;
        user.bio = bio || user.bio;
        user.role = role || user.role;
        
        if (password) {
            user.password = await bcrypt.hash(password, 10);
        }
        
        await user.save();
        
        res.json({ success: true, user });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'Utente non trovato' });
        }
        
        // Prevent deleting admin accounts
        if (user.role === 'admin') {
            return res.status(403).json({ error: 'Non puoi eliminare un account admin' });
        }
        
        // Delete user's spots
        await Spot.deleteMany({
            $or: [
                { author: user.username },
                { currentOwner: user.username }
            ]
        });
        
        // Delete user's trade requests
        await TradeRequest.deleteMany({
            $or: [
                { fromUser: user.username },
                { toUser: user.username }
            ]
        });
        
        // Delete the user
        await User.findByIdAndDelete(req.params.id);
        
        res.json({ success: true, message: 'Utente eliminato con successo' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Admin login as user
app.post('/api/admin/login-as', requireAdmin, async (req, res) => {
  try {
    const { username } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    // Salva l'admin corrente in session
    req.session.originalAdmin = {
      id: req.session.user.id,
      username: req.session.user.username,
      role: req.session.user.role
    };
    
    // Set session as the target user
    req.session.user = {
      id: user._id,
      username: user.username,
      role: user.role,
      isTemporaryLogin: true,
      originalAdmin: req.session.originalAdmin
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
    console.error('Error logging in as user:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ritorna all'account admin dopo login temporaneo
app.post('/api/admin/return-to-admin', async (req, res) => {
  try {
    if (req.session.user && req.session.user.isTemporaryLogin && req.session.user.originalAdmin) {
      // Ripristina l'admin originale
      req.session.user = req.session.user.originalAdmin;
      delete req.session.user.isTemporaryLogin;
      delete req.session.user.originalAdmin;
      
      res.json({ 
        success: true, 
        user: req.session.user,
        isAdmin: true
      });
    } else {
      res.status(400).json({ error: 'Non sei in un login temporaneo' });
    }
  } catch (error) {
    console.error('Error returning to admin:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

app.get('/api/admin/trades', requireAdmin, async (req, res) => {
    try {
        // Ora mostra TUTTI gli scambi, non solo quelli in attesa di admin
        const trades = await TradeRequest.find()
            .populate('spotId')
            .populate('offeredSpots')
            .populate('selectedSpotId')
            .sort({ createdAt: -1 })
            .lean();
        
        // Aggiungi un campo per distinguere gli scambi in attesa di admin
        const tradesWithStatus = trades.map(trade => {
            const needsAdminApproval = !trade.adminApproved && !trade.adminRejected && trade.status === 'pending';
            return {
                ...trade,
                needsAdminApproval
            };
        });
        
        res.json(tradesWithStatus);
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
        
        // Filter out duplicate spots (copies from trades) - only show original spots
        query.originalSpotId = { $exists: false };
        
        const spots = await Spot.find(query)
            .sort({ createdAt: -1 })
            .lean();
        
        res.json(spots);
    } catch (error) {
        console.error('Error fetching admin spots:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

// Fan invite routes - now generates codes that never expire
app.post('/api/admin/invites', requireAdmin, async (req, res) => {
    try {
        // Generate unique token (12 characters, formatted as XXXX-XXXX-XXXX)
        const token = crypto.randomBytes(6).toString('hex').toUpperCase(); // 12 characters
        
        const invite = new FanInvite({
            token,
            createdBy: req.session.user.username,
            // No expiresAt - codes never expire
        });
        
        await invite.save();
        
        res.json({
            success: true,
            invite: {
                token,
                createdBy: invite.createdBy,
                createdAt: invite.createdAt
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
            used: false
        });
        
        if (!invite) {
            return res.json({ valid: false, message: 'Codice non valido o già utilizzato' });
        }
        
        res.json({ 
            valid: true, 
            createdBy: invite.createdBy
        });
        
    } catch (error) {
        console.error('Error checking token:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});
// Admin update spot
app.put('/api/admin/spots/:id/update', requireAdmin, async (req, res) => {
  try {
    const { give, want, region, coordinates, category, description, status, author } = req.body;
    
    if (!give || !want || !region || !category || !author) {
      return res.status(400).json({ error: 'Tutti i campi sono obbligatori' });
    }
    
    const spot = await Spot.findById(req.params.id);
    
    if (!spot) {
      return res.status(404).json({ error: 'Spot non trovato' });
    }
    
    // Verifica se l'autore è cambiato
    if (author !== spot.author) {
      // Controlla se il nuovo autore esiste
      let user = await User.findOne({ username: author });
      if (!user) {
        // Crea un nuovo utente se non esiste
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
      
      spot.authorId = user._id;
    }
    
    // Aggiorna i campi dello spot
    spot.give = give;
    spot.want = want;
    spot.region = region;
    spot.coordinates = coordinates;
    spot.category = category;
    spot.description = description;
    spot.status = status;
    spot.author = author;
    spot.updatedAt = new Date();
    
    await spot.save();
    
    res.json({ 
      success: true, 
      spot,
      message: 'Spot aggiornato con successo'
    });
    
  } catch (error) {
    console.error('Error updating spot:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});
// Download CSV template - nuovo formato con latitudine e longitudine separate
app.get('/api/admin/template', requireAdmin, (req, res) => {
    const csv = 'username,give,want,region,category,lat,lng,description\n' +
                'test,Ex fabbrica tessile,Hotel abbandonato,Lombardia,industriale,45.4642,9.1900,Descrizione spot di esempio';
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=template_spot.csv');
    res.send(csv);
});

// Serve HTML
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server avviato su http://localhost:${PORT}`);
});
