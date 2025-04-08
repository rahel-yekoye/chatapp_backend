const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  sender: String,
  receiver: String, // Optional for private
  groupId: String,   // Optional for group
  content: String,
  fileUrl: String,   // For attachments
  emojis: [String],  // For emoji reactions (optional use case)
  isGroup: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Message', messageSchema);
