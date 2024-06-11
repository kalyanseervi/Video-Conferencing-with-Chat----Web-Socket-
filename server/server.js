const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
require('dotenv').config();

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

const rooms = {};

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
    socket.join(room);
    socket.room = room;

    if (!rooms[room]) {
      rooms[room] = [];
    }
    rooms[room].push(socket.username);

    console.log(`${socket.username} joined room: ${room}`);
    io.to(room).emit('user-joined', { username: socket.username, users: rooms[room] });
  });

  socket.on('leave', () => {
    const room = socket.room;
    socket.leave(room);

    if (rooms[room]) {
      rooms[room] = rooms[room].filter(user => user !== socket.username);
      if (rooms[room].length === 0) {
        delete rooms[room];
      } else {
        io.to(room).emit('user-left', { username: socket.username, users: rooms[room] });
      }
    }

    console.log(`${socket.username} left room: ${room}`);
    socket.room = null;
  });

  socket.on('offer', (data) => {
    socket.to(data.target).emit('offer', { offer: data.offer, from: socket.username });
  });

  socket.on('answer', (data) => {
    socket.to(data.target).emit('answer', { answer: data.answer, from: socket.username });
  });

  socket.on('ice-candidate', (data) => {
    socket.to(data.target).emit('ice-candidate', { candidate: data.candidate, from: socket.username });
  });

  socket.on('chat-message', (data) => {
    io.to(data.room).emit('chat-message', { message: data.message, username: socket.username, timestamp: new Date().toLocaleTimeString() });
  });

  socket.on('disconnect', () => {
    if (socket.room) {
      const room = socket.room;
      rooms[room] = rooms[room].filter(user => user !== socket.username);
      io.to(room).emit('user-left', { username: socket.username, users: rooms[room] });
    }
    console.log('Client disconnected');
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
