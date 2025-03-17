const mongoose = require('mongoose');

// Define the chat message schema
const MessageSchema = new mongoose.Schema({
  sender: { type: String, required: true },   // Who sent the message
  receiver: { type: String, required: true }, // Who receives the message
  content: { type: String, required: true },  // The message text
  timestamp: { type: Date, default: Date.now } // When it was sent
});

// Export this schema as a model
module.exports = mongoose.model('Message', MessageSchema);
