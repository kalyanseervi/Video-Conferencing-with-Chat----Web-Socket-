// server.js

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');


const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET || 'a1b2c3d44e5';
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET || 'a1b2c3d44e5f6g7';
const refreshTokens = {};

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
    process.exit(1);
  });

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String
});

const User = mongoose.model('User', userSchema);

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({ username, password: hashedPassword });

  try {
    await newUser.save();
    res.status(201).send({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).send({ message: 'Registration failed', error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) return res.status(401).send({ message: 'Invalid credentials' });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(401).send({ message: 'Invalid credentials' });

  const accessToken = jwt.sign({ username }, accessTokenSecret, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ username }, refreshTokenSecret);

  refreshTokens[refreshToken] = username;

  res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.send({ accessToken });
});

app.post('/token', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).send({ message: 'Refresh token not provided' });

  if (!refreshTokens[refreshToken]) return res.status(403).send({ message: 'Invalid refresh token' });

  jwt.verify(refreshToken, refreshTokenSecret, (err, user) => {
    if (err) return res.status(403).send({ message: 'Invalid refresh token' });

    const accessToken = jwt.sign({ username: user.username }, accessTokenSecret, { expiresIn: '15m' });
    res.send({ accessToken });
  });
});

const authenticate = (socket, next) => {
  const token = socket.handshake.query.token;
  if (!token) return next(new Error('Authentication error'));

  jwt.verify(token, accessTokenSecret, (err, decoded) => {
    if (err) return next(new Error('Authentication error'));
    socket.username = decoded.username;
    next();
  });
};

io.use(authenticate);

io.on('connection', (socket) => {
  console.log('New client connected');

  socket.on('join', (room) => {
    console.log(`Client joined room: ${room}`);
    socket.join(room);
    socket.emit('joined');
  });

  socket.on('offer', (offer) => {
    socket.to('room1').emit('offer', offer);
  });

  socket.on('answer', (answer) => {
    socket.to('room1').emit('answer', answer);
  });

  socket.on('ice-candidate', (candidate) => {
    socket.to('room1').emit('ice-candidate', candidate);
  });

  socket.on('chat-message', ({ username, message, timestamp }) => {
    console.log(`Received chat-message: ${message}`);
    socket.to('room1').emit('chat-message', { username, message, timestamp });
  });

  socket.on('start-video', () => {
    socket.to('room1').emit('start-video');
  });

  socket.on('end-video', () => {
    socket.to('room1').emit('end-video');
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
