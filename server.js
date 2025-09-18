
const express = require('express');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());


let users = [];


const PORT = process.env.PORT || 3000;
const JWT_SECRET = "batman"
const JWT_EXPIRES_IN = '2h';
const BCRYPT_SALT_ROUNDS = 10;

function generateId() {
  return Date.now() + Math.floor(Math.random() * 10000);
}

function findUserByUsername(username) {
  return users.find(u => u.username === username);
}

function findUserById(id) {
  return users.find(u => u.id === id);
}


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.split(' ')[1]
    : null;

  if (!token) {
    return res.status(401).json({ error: 'Token missing. Please login.' });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token.' });
    const user = findUserById(payload.id);
    if (!user) return res.status(401).json({ error: 'User no longer exists.' });

    req.user = { id: user.id, username: user.username };
    next();
  });
}

app.post('/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required.' });
    }
    if (findUserByUsername(username)) {
      return res.status(409).json({ error: 'Username already taken.' });
    }

    const hashed = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    const newUser = {
      id: generateId(),
      username,
      password: hashed,
      movies: []
    };
    users.push(newUser);

    res.status(201).json({
      message: 'User registered successfully.',
      user: { id: newUser.id, username: newUser.username }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error while registering.' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required.' });
    }

    const user = findUserByUsername(username);
    if (!user) return res.status(401).json({ error: 'Invalid username or password.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid username or password.' });

    const payload = { id: user.id, username: user.username };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    res.json({ message: 'Logged in successfully.', token });
  } catch (err) {
    res.status(500).json({ error: 'Server error while logging in.' });
  }
});

app.post('/movies', authenticateToken, (req, res) => {
  const { title, language, overview, watched = false } = req.body || {};
  if (!title) return res.status(400).json({ error: 'Movie title is required.' });

  const user = findUserById(req.user.id);
  const movie = {
    id: generateId(),
    title,
    language: language || 'Unknown',
    overview: overview || '',
    watched: !!watched
  };
  user.movies.push(movie);
  res.status(201).json({ message: 'Movie added to watchlist.', movie });
});

app.get('/movies', authenticateToken, (req, res) => {
  const { status } = req.query;
  const user = findUserById(req.user.id);
  let movies = user.movies || [];

  if (status) {
    if (status === 'watched') movies = movies.filter(m => m.watched);
    else if (status === 'unwatched') movies = movies.filter(m => !m.watched);
    else return res.status(400).json({ error: 'Invalid status. Use "watched" or "unwatched".' });
  }

  res.json({ movies });
});

app.get('/movies/:id', authenticateToken, (req, res) => {
  const movieId = Number(req.params.id);
  const user = findUserById(req.user.id);
  const movie = user.movies.find(m => Number(m.id) === movieId);
  if (!movie) return res.status(404).json({ error: 'Movie not found.' });
  res.json({ movie });
});

app.patch('/movies/:id', authenticateToken, (req, res) => {
  const movieId = Number(req.params.id);
  const { title, language, overview, watched } = req.body || {};
  const user = findUserById(req.user.id);
  const movie = user.movies.find(m => Number(m.id) === movieId);
  if (!movie) return res.status(404).json({ error: 'Movie not found.' });

  if (title !== undefined) movie.title = title;
  if (language !== undefined) movie.language = language;
  if (overview !== undefined) movie.overview = overview;
  if (watched !== undefined) movie.watched = !!watched;

  res.json({ message: 'Movie updated.', movie });
});

app.delete('/movies/:id', authenticateToken, (req, res) => {
  const movieId = Number(req.params.id);
  const user = findUserById(req.user.id);
  const index = user.movies.findIndex(m => Number(m.id) === movieId);
  if (index === -1) return res.status(404).json({ error: 'Movie not found.' });

  const [deleted] = user.movies.splice(index, 1);
  res.json({ message: 'Movie removed.', movie: deleted });
});


app.get('/debug/users', (req, res) => {
  res.json({ users: users.map(u => ({ id: u.id, username: u.username, moviesCount: u.movies.length })) });
});


app.get('/', (req, res) => {
  res.send('JWT-only Movie Watchlist API is running.');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
