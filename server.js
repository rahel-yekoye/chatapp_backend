const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http'); // Needed for socket.io to work
const { Server } = require('socket.io');
const Message = require('./models/Message'); // Import Message model

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

// Real-time Socket.IO connection
io.on('connection', (socket) => {
  console.log('🟢 A user connected:', socket.id);

  // Handle room joining when user connects
  socket.on('join_room', (username) => {
    socket.join(username); // User joins a room named after their username
    console.log(`✅ User ${username} joined room: ${username}`);
  });

  // Handle real-time message sending
  socket.on('send_message', async (data) => {
    console.log('📨 Real-time message:', data);
    const { sender, receiver, content } = data;

    // Save message to MongoDB
    const message = new Message({ sender, receiver, content });
    await message.save();

    // Emit message to sender (in their room)
    io.to(sender).emit('receive_message', message);

    // Emit message to receiver (in their room)
    io.to(receiver).emit('receive_message', message);
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('🔴 User disconnected:', socket.id);
    // No need to manually track users now as rooms handle this dynamically
  });
});

// API route to send message (for compatibility if needed)
app.post('/messages', async (req, res) => {
  try {
    console.log('New message received via API:', req.body);
    const { sender, receiver, content } = req.body;
    const message = new Message({ sender, receiver, content });
    await message.save();

    // Emit real-time message to sender and receiver rooms
    io.to(sender).emit('receive_message', message);
    io.to(receiver).emit('receive_message', message);

    res.json({ success: true, message: 'Message sent!', data: message });
  } catch (error) {
    console.error('❌ Error sending message:', error);
    res.status(500).json({ success: false, message: 'Failed to send message', error });
  }
});

// API route to get chat history
app.get('/messages', async (req, res) => {
  try {
    const { sender, receiver } = req.query;
    let filter = {};
    if (sender && receiver) {
      filter = {
        $or: [
          { sender: sender, receiver: receiver },
          { sender: receiver, receiver: sender }
        ]
      };
    }
    console.log('Fetching messages with filter:', filter);
    const messages = await Message.find(filter).sort({ timestamp: 1 });
    res.json({ success: true, data: messages });
  } catch (error) {
    console.error('❌ Error fetching messages:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch messages', error });
  }
});

// Start server with socket.io attached
server.listen(port, () => {
  console.log(`🚀 Server is running with real-time on http://localhost:${port}`);
});
