require('dotenv').config({ path: './secret.env' }); // Load the secret.env file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs'); // Replace bcrypt with bcryptjs
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Message = require('./models/message'); // Import Message model
const User = require('./models/user'); // Import User model
const { parsePhoneNumberFromString } = require('libphonenumber-js');

const app = express();
const port = 3000;

// Create HTTP server to attach Socket.IO
const server = http.createServer(app);

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: '*', // Allow requests from any origin (adjust this for production)
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/chat-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch((err) => console.error('❌ MongoDB connection error:', err));

// Test route
app.get('/', (req, res) => {
  res.send('🚀 Chat App Backend with Real-Time is Running!');
});

// Registration endpoint
app.post('/register', async (req, res) => {
  const { username, email, phoneNumber, password } = req.body;

  console.log('Received registration data:', { username, email, phoneNumber, password }); // Debug log

  if (!username || !email || !password) {
    console.log('Missing required fields'); // Debug log
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }

  // Validate and normalize phone number
  let normalizedPhoneNumber = null;
  if (phoneNumber) {
    const { parsePhoneNumberFromString } = require('libphonenumber-js');

    // Automatically prepend the country code if missing
    const formattedPhoneNumber = phoneNumber.trim().startsWith('+') ? phoneNumber.trim() : `+251${phoneNumber.trim()}`;
    console.log('Formatted phone number:', formattedPhoneNumber); // Debug log

    const parsedPhoneNumber = parsePhoneNumberFromString(formattedPhoneNumber, 'ET'); // Replace 'ET' with your default country code
    if (!parsedPhoneNumber || !parsedPhoneNumber.isValid()) {
      console.log('Invalid phone number format:', formattedPhoneNumber); // Debug log
      return res.status(400).json({ error: 'Invalid phone number format' });
    }
    const normalizedPhoneNumber = parsedPhoneNumber.number;
    console.log('Normalized phone number:', normalizedPhoneNumber); // Debug log
  }

  try {
    // Check if the phone number already exists
    if (normalizedPhoneNumber) {
      const existingUser = await User.findOne({ phoneNumber: normalizedPhoneNumber });
      if (existingUser) {
        console.log('Phone number already exists:', normalizedPhoneNumber); // Debug log
        return res.status(400).json({ error: 'Phone number already exists' });
      }
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({ username, email, phoneNumber: normalizedPhoneNumber, password: hashedPassword });
    await newUser.save();

    console.log('User registered successfully:', newUser); // Debug log
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  console.log('Login request body:', req.body); // Debugging log

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, 'your_jwt_secret', {
      expiresIn: '1h',
    });

    res.json({
      token,
      user: {
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Properly extract token

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid token.' });
    }
    req.user = user; // Attach the user payload to the request
    next();
  });
}

console.log('JWT Secret:', process.env.JWT_SECRET);

// Rate limiter
const searchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.',
});

// Secured /search endpoint
app.get('/search', authenticateToken, async (req, res) => {
  const { phoneNumber } = req.query;

  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  try {
    console.log('Received phone number:', phoneNumber); // Debug log

    const { parsePhoneNumberFromString } = require('libphonenumber-js');
    const parsedPhoneNumber = parsePhoneNumberFromString(phoneNumber, 'ET'); // Replace 'ET' with your default country code
    if (!parsedPhoneNumber || !parsedPhoneNumber.isValid()) {
      console.log('Invalid phone number format:', phoneNumber); // Debug log
      return res.status(400).json({ error: 'Invalid phone number format' });
    }
    const normalizedPhoneNumber = parsedPhoneNumber.number;
    console.log('Normalized phone number:', normalizedPhoneNumber); // Debug log

    const user = await User.findOne({ phoneNumber: normalizedPhoneNumber });
    if (!user) {
      console.log('User not found for phone number:', normalizedPhoneNumber); // Debug log
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('User found:', user); // Debug log
    res.json({ success: true, user: { username: user.username, phoneNumber: user.phoneNumber } });
  } catch (error) {
    console.error('Error searching for user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Real-time Socket.IO connection
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // Join a room
  socket.on('join_room', (roomId) => {
    socket.join(roomId);
    console.log(`User ${socket.id} joined room: ${roomId}`);
  });

  // Handle sending messages
  socket.on('send_message', async (data) => {
    console.log('Received send_message event:', data);

    const { roomId, sender, receiver, content } = data;

    const message = new Message({
      sender,
      receiver,
      content,
      timestamp: new Date(),
    });

    try {
      await message.save();
      console.log('Message saved to database:', message);

      io.to(roomId).emit('receive_message', {
        sender: message.sender,
        receiver: message.receiver,
        content: message.content,
        timestamp: message.timestamp,
      });

      console.log('Broadcasted receive_message event to room:', roomId);
    } catch (error) {
      console.error('Error saving message to database:', error);
    }
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('A user disconnected:', socket.id);
  });
});

// API route to send message (for compatibility if needed)
app.post('/messages', async (req, res) => {
  try {
    console.log('New message received via API:', req.body);
    const { sender, receiver, content } = req.body;

    // Check if the message already exists in the database
    const existingMessage = await Message.findOne({ sender, receiver, content });

    if (!existingMessage) {
      console.log('No duplicate message found, saving message.');
    } else {
      console.log('Duplicate message detected:', existingMessage);
    }

    if (!existingMessage) {
      const message = new Message({ sender, receiver, content });
      await message.save();

      // Emit real-time message to sender and receiver rooms
      io.to(sender).emit('receive_message', message);
      io.to(receiver).emit('receive_message', message);

      res.json({ success: true, message: 'Message sent!', data: message });
    } else {
      console.log('Duplicate message detected, not saving.');
      res.json({ success: false, message: 'Duplicate message detected' });
    }
  } catch (error) {
    console.error('❌ Error sending message:', error);
    res.status(500).json({ success: false, message: 'Failed to send message', error });
  }
});

// API route to get chat history
app.get('/messages', async (req, res) => {
  const { user1, user2 } = req.query;

  if (!user1 || !user2) {
    return res.status(400).json({ error: 'Both user1 and user2 are required' });
  }

  try {
    const messages = await Message.find({
      $or: [
        { sender: user1, receiver: user2 },
        { sender: user2, receiver: user1 },
      ],
    }).sort({ timestamp: 1 }); // Sort messages by timestamp

    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API route to get all conversations for a user
app.get('/conversations', async (req, res) => {
  const { user } = req.query;

  if (!user) {
    return res.status(400).json({ error: 'User is required' });
  }

  try {
    // Fetch the latest message for each conversation involving the user
    const conversations = await Message.aggregate([
      {
        $match: {
          $or: [
            { sender: user },
            { receiver: user },
          ],
        },
      },
      {
        $sort: { timestamp: -1 }, // Sort messages by timestamp (latest first)
      },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ['$sender', user] },
              '$receiver', // If the user is the sender, group by receiver
              '$sender',  // Otherwise, group by sender
            ],
          },
          latestMessage: { $first: '$$ROOT' }, // Get the latest message in each group
        },
      },
    ]);

    res.json(conversations.map((conv) => ({
      otherUser: conv._id,
      message: conv.latestMessage.content,
      timestamp: conv.latestMessage.timestamp,
    })));
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start server with socket.io attached
server.listen(port, () => {
  console.log(`🚀 Server is running with real-time on http://localhost:${port}`);
});
