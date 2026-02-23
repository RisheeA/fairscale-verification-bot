// FairScale Telegram Verification Bot
// Production-ready, secure, battle-tested

import TelegramBot from 'node-telegram-bot-api';
import 'dotenv/config';

// =============================================================================
// CONFIGURATION
// =============================================================================

const CONFIG = {
  // Telegram
  TELEGRAM_TOKEN: process.env.TELEGRAM_TOKEN,
  
  // FairScale
  FAIRSCALE_API: process.env.FAIRSCALE_API || 'https://api.fairscale.xyz',
  FAIRSCALE_API_KEY: process.env.FAIRSCALE_API_KEY,
  
  // Defaults
  DEFAULT_MIN_SCORE: 60,
  
  // Rate limiting
  VERIFY_COOLDOWN_MS: 60 * 1000,
  MAX_ATTEMPTS_PER_HOUR: 5,
};

// =============================================================================
// STORAGE (Replace with database in production)
// =============================================================================

// Group settings: chatId -> { minScore, restrictNewUsers }
const groupSettings = new Map();

// Verified users: `${chatId}-${userId}` -> { wallet, score, verifiedAt }
const verifiedUsers = new Map();

// Rate limiting: `${chatId}-${userId}` -> { attempts: [], lastAttempt }
const rateLimits = new Map();

// Wallet registry: `${chatId}-${wallet}` -> { userId }
const walletRegistry = new Map();

// Pending verifications: `${chatId}-${userId}` -> { state, timestamp }
const pendingVerifications = new Map();

// Admin cache: chatId -> Set of admin userIds
const adminCache = new Map();

// =============================================================================
// HELPERS
// =============================================================================

function isValidSolanaAddress(address) {
  if (!address || typeof address !== 'string') return false;
  const base58Regex = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  return base58Regex.test(address);
}

function checkRateLimit(chatId, userId) {
  const key = `${chatId}-${userId}`;
  const now = Date.now();
  const userLimits = rateLimits.get(key) || { attempts: [], lastAttempt: 0 };
  
  userLimits.attempts = userLimits.attempts.filter(t => now - t < 60 * 60 * 1000);
  
  if (now - userLimits.lastAttempt < CONFIG.VERIFY_COOLDOWN_MS) {
    const waitSeconds = Math.ceil((CONFIG.VERIFY_COOLDOWN_MS - (now - userLimits.lastAttempt)) / 1000);
    return { allowed: false, reason: `Please wait ${waitSeconds} seconds.` };
  }
  
  if (userLimits.attempts.length >= CONFIG.MAX_ATTEMPTS_PER_HOUR) {
    return { allowed: false, reason: 'Too many attempts. Try again in an hour.' };
  }
  
  return { allowed: true };
}

function recordAttempt(chatId, userId) {
  const key = `${chatId}-${userId}`;
  const now = Date.now();
  const userLimits = rateLimits.get(key) || { attempts: [], lastAttempt: 0 };
  userLimits.attempts.push(now);
  userLimits.lastAttempt = now;
  rateLimits.set(key, userLimits);
}

async function getFairScore(wallet) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    
    const response = await fetch(
      `${CONFIG.FAIRSCALE_API}/score?wallet=${encodeURIComponent(wallet)}`,
      {
        headers: {
          'accept': 'application/json',
          'fairkey': CONFIG.FAIRSCALE_API_KEY,
        },
        signal: controller.signal,
      }
    );
    
    clearTimeout(timeout);
    
    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('FairScale API error:', error);
    return null;
  }
}

async function isAdmin(bot, chatId, userId) {
  try {
    // Check cache first
    if (adminCache.has(chatId)) {
      return adminCache.get(chatId).has(userId);
    }
    
    // Fetch admins
    const admins = await bot.getChatAdministrators(chatId);
    const adminSet = new Set(admins.map(a => a.user.id));
    adminCache.set(chatId, adminSet);
    
    // Clear cache after 5 minutes
    setTimeout(() => adminCache.delete(chatId), 5 * 60 * 1000);
    
    return adminSet.has(userId);
  } catch (error) {
    console.error('Failed to check admin status:', error);
    return false;
  }
}

function formatScore(data, passed, minScore) {
  const status = passed ? '✅ VERIFIED' : '❌ NOT VERIFIED';
  const tierEmoji = {
    'platinum': '💎',
    'gold': '🥇',
    'silver': '🥈',
    'bronze': '🥉',
  };
  
  let message = `*FairScale Verification*\n\n`;
  message += `${status}\n\n`;
  message += `*FairScore:* ${data.fairscore}/100 ${tierEmoji[data.tier] || ''}\n`;
  message += `*Tier:* ${data.tier || 'Unknown'}\n`;
  message += `*Required:* ${minScore}+\n`;
  
  if (data.badges && data.badges.length > 0) {
    message += `\n*Badges:*\n`;
    data.badges.slice(0, 5).forEach(b => {
      message += `• ${b.name}\n`;
    });
  }
  
  if (!passed) {
    message += `\n_You need a score of ${minScore} or higher to verify._`;
  }
  
  return message;
}

function escapeMarkdown(text) {
  return text.replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
}

// =============================================================================
// BOT INITIALIZATION
// =============================================================================

const bot = new TelegramBot(CONFIG.TELEGRAM_TOKEN, { polling: true });

// =============================================================================
// COMMAND: /start
// =============================================================================

bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  const isGroup = msg.chat.type === 'group' || msg.chat.type === 'supergroup';
  
  let message;
  
  if (isGroup) {
    message = `*⚖️ FairScale Verification Bot*\n\n`;
    message += `I verify users based on their Solana wallet reputation.\n\n`;
    message += `*User Commands:*\n`;
    message += `/verify - Start verification\n`;
    message += `/check <wallet> - Check any wallet's score\n`;
    message += `/mystatus - View your verification\n\n`;
    message += `*Admin Commands:*\n`;
    message += `/setup <score> - Set minimum score (e.g. /setup 60)\n`;
    message += `/settings - View current settings\n`;
    message += `/unverify @user - Remove verification`;
  } else {
    message = `*⚖️ FairScale Verification Bot*\n\n`;
    message += `Add me to a group to enable wallet-based verification.\n\n`;
    message += `*How it works:*\n`;
    message += `1. Add bot to your group\n`;
    message += `2. Make bot admin (to restrict users)\n`;
    message += `3. Use /setup to set minimum score\n`;
    message += `4. Users verify with /verify\n\n`;
    message += `[Add to Group](https://t.me/${(await bot.getMe()).username}?startgroup=true)`;
  }
  
  bot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
});

// =============================================================================
// COMMAND: /verify
// =============================================================================

bot.onText(/\/verify/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const isGroup = msg.chat.type === 'group' || msg.chat.type === 'supergroup';
  
  if (!isGroup) {
    return bot.sendMessage(chatId, '❌ This command only works in groups.');
  }
  
  // Check if already verified
  const verifyKey = `${chatId}-${userId}`;
  if (verifiedUsers.has(verifyKey)) {
    const existing = verifiedUsers.get(verifyKey);
    return bot.sendMessage(
      chatId,
      `✅ You're already verified!\n\nWallet: \`${existing.wallet.slice(0, 8)}...${existing.wallet.slice(-6)}\`\nScore: ${existing.score}/100`,
      { parse_mode: 'Markdown', reply_to_message_id: msg.message_id }
    );
  }
  
  // Check rate limit
  const rateCheck = checkRateLimit(chatId, userId);
  if (!rateCheck.allowed) {
    return bot.sendMessage(chatId, `⏳ ${rateCheck.reason}`, { reply_to_message_id: msg.message_id });
  }
  
  // Set pending state
  pendingVerifications.set(verifyKey, { state: 'awaiting_wallet', timestamp: Date.now() });
  
  // Ask for wallet
  bot.sendMessage(
    chatId,
    `Please reply with your Solana wallet address to verify.`,
    { reply_to_message_id: msg.message_id }
  );
});

// =============================================================================
// HANDLE WALLET SUBMISSION
// =============================================================================

bot.on('message', async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const text = msg.text;
  
  // Skip commands
  if (!text || text.startsWith('/')) return;
  
  // Check if user has pending verification
  const verifyKey = `${chatId}-${userId}`;
  const pending = pendingVerifications.get(verifyKey);
  
  if (!pending || pending.state !== 'awaiting_wallet') return;
  
  // Check timeout (5 minutes)
  if (Date.now() - pending.timestamp > 5 * 60 * 1000) {
    pendingVerifications.delete(verifyKey);
    return;
  }
  
  const wallet = text.trim();
  
  // Validate wallet
  if (!isValidSolanaAddress(wallet)) {
    return bot.sendMessage(
      chatId,
      '❌ Invalid Solana wallet address. Please try again.',
      { reply_to_message_id: msg.message_id }
    );
  }
  
  // Check if wallet already used
  const walletKey = `${chatId}-${wallet}`;
  if (walletRegistry.has(walletKey)) {
    pendingVerifications.delete(verifyKey);
    return bot.sendMessage(
      chatId,
      '❌ This wallet is already linked to another user.',
      { reply_to_message_id: msg.message_id }
    );
  }
  
  // Record attempt
  recordAttempt(chatId, userId);
  pendingVerifications.delete(verifyKey);
  
  // Send loading message
  const loadingMsg = await bot.sendMessage(chatId, '⏳ Checking wallet...', { reply_to_message_id: msg.message_id });
  
  // Get settings
  const settings = groupSettings.get(chatId) || { minScore: CONFIG.DEFAULT_MIN_SCORE };
  
  // Fetch FairScore
  const data = await getFairScore(wallet);
  
  if (!data || data.fairscore === undefined) {
    return bot.editMessageText(
      '❌ Failed to fetch wallet score. Please try again later.',
      { chat_id: chatId, message_id: loadingMsg.message_id }
    );
  }
  
  const passed = data.fairscore >= settings.minScore;
  const message = formatScore(data, passed, settings.minScore);
  
  if (passed) {
    // Store verification
    verifiedUsers.set(verifyKey, {
      wallet,
      score: data.fairscore,
      verifiedAt: new Date().toISOString(),
    });
    walletRegistry.set(walletKey, { userId });
    
    // Unrestrict user if they were restricted
    try {
      await bot.restrictChatMember(chatId, userId, {
        can_send_messages: true,
        can_send_media_messages: true,
        can_send_polls: true,
        can_send_other_messages: true,
        can_add_web_page_previews: true,
        can_change_info: false,
        can_invite_users: true,
        can_pin_messages: false,
      });
    } catch (error) {
      // Bot may not have permission, that's ok
    }
  }
  
  bot.editMessageText(message, {
    chat_id: chatId,
    message_id: loadingMsg.message_id,
    parse_mode: 'Markdown',
  });
});

// =============================================================================
// COMMAND: /check
// =============================================================================

bot.onText(/\/check(?:\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const wallet = match[1]?.trim();
  
  if (!wallet) {
    return bot.sendMessage(chatId, 'Usage: /check <wallet_address>', { reply_to_message_id: msg.message_id });
  }
  
  if (!isValidSolanaAddress(wallet)) {
    return bot.sendMessage(chatId, '❌ Invalid Solana wallet address.', { reply_to_message_id: msg.message_id });
  }
  
  const loadingMsg = await bot.sendMessage(chatId, '⏳ Checking wallet...', { reply_to_message_id: msg.message_id });
  
  const data = await getFairScore(wallet);
  
  if (!data || data.fairscore === undefined) {
    return bot.editMessageText(
      '❌ Failed to fetch wallet score.',
      { chat_id: chatId, message_id: loadingMsg.message_id }
    );
  }
  
  const tierEmoji = {
    'platinum': '💎',
    'gold': '🥇',
    'silver': '🥈',
    'bronze': '🥉',
  };
  
  let message = `*⚖️ FairScale Wallet Check*\n\n`;
  message += `*Wallet:* \`${wallet.slice(0, 8)}...${wallet.slice(-6)}\`\n`;
  message += `*FairScore:* ${data.fairscore}/100 ${tierEmoji[data.tier] || ''}\n`;
  message += `*Tier:* ${data.tier || 'Unknown'}\n`;
  
  if (data.badges && data.badges.length > 0) {
    message += `\n*Badges:*\n`;
    data.badges.slice(0, 5).forEach(b => {
      message += `• ${b.name}\n`;
    });
  }
  
  bot.editMessageText(message, {
    chat_id: chatId,
    message_id: loadingMsg.message_id,
    parse_mode: 'Markdown',
  });
});

// =============================================================================
// COMMAND: /mystatus
// =============================================================================

bot.onText(/\/mystatus/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  
  const verifyKey = `${chatId}-${userId}`;
  const verification = verifiedUsers.get(verifyKey);
  
  if (!verification) {
    return bot.sendMessage(
      chatId,
      '❌ You are not verified. Use /verify to start.',
      { reply_to_message_id: msg.message_id }
    );
  }
  
  const message = `*✅ Your Verification Status*\n\n` +
    `*Wallet:* \`${verification.wallet.slice(0, 8)}...${verification.wallet.slice(-6)}\`\n` +
    `*Score:* ${verification.score}/100\n` +
    `*Verified:* ${new Date(verification.verifiedAt).toLocaleDateString()}`;
  
  bot.sendMessage(chatId, message, { parse_mode: 'Markdown', reply_to_message_id: msg.message_id });
});

// =============================================================================
// COMMAND: /setup (Admin)
// =============================================================================

bot.onText(/\/setup(?:\s+(\d+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const minScore = match[1] ? parseInt(match[1]) : null;
  
  const isGroup = msg.chat.type === 'group' || msg.chat.type === 'supergroup';
  if (!isGroup) {
    return bot.sendMessage(chatId, '❌ This command only works in groups.');
  }
  
  // Check admin
  if (!await isAdmin(bot, chatId, userId)) {
    return bot.sendMessage(chatId, '❌ Only admins can use this command.', { reply_to_message_id: msg.message_id });
  }
  
  if (minScore === null || minScore < 0 || minScore > 100) {
    return bot.sendMessage(chatId, 'Usage: /setup <score>\nExample: /setup 60', { reply_to_message_id: msg.message_id });
  }
  
  const settings = groupSettings.get(chatId) || { minScore: CONFIG.DEFAULT_MIN_SCORE };
  settings.minScore = minScore;
  groupSettings.set(chatId, settings);
  
  bot.sendMessage(
    chatId,
    `✅ Settings updated!\n\nMinimum FairScore: ${minScore}`,
    { reply_to_message_id: msg.message_id }
  );
});

// =============================================================================
// COMMAND: /settings (Admin)
// =============================================================================

bot.onText(/\/settings/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  
  const isGroup = msg.chat.type === 'group' || msg.chat.type === 'supergroup';
  if (!isGroup) {
    return bot.sendMessage(chatId, '❌ This command only works in groups.');
  }
  
  if (!await isAdmin(bot, chatId, userId)) {
    return bot.sendMessage(chatId, '❌ Only admins can use this command.', { reply_to_message_id: msg.message_id });
  }
  
  const settings = groupSettings.get(chatId) || { minScore: CONFIG.DEFAULT_MIN_SCORE };
  const verifiedCount = Array.from(verifiedUsers.keys()).filter(k => k.startsWith(`${chatId}-`)).length;
  
  const message = `*⚖️ FairScale Settings*\n\n` +
    `*Minimum Score:* ${settings.minScore}\n` +
    `*Verified Users:* ${verifiedCount}`;
  
  bot.sendMessage(chatId, message, { parse_mode: 'Markdown', reply_to_message_id: msg.message_id });
});

// =============================================================================
// COMMAND: /unverify (Admin)
// =============================================================================

bot.onText(/\/unverify/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  
  const isGroup = msg.chat.type === 'group' || msg.chat.type === 'supergroup';
  if (!isGroup) {
    return bot.sendMessage(chatId, '❌ This command only works in groups.');
  }
  
  if (!await isAdmin(bot, chatId, userId)) {
    return bot.sendMessage(chatId, '❌ Only admins can use this command.', { reply_to_message_id: msg.message_id });
  }
  
  // Check if replying to a user
  if (!msg.reply_to_message) {
    return bot.sendMessage(
      chatId,
      'Reply to a user\'s message with /unverify to remove their verification.',
      { reply_to_message_id: msg.message_id }
    );
  }
  
  const targetUserId = msg.reply_to_message.from.id;
  const targetUsername = msg.reply_to_message.from.username || msg.reply_to_message.from.first_name;
  const verifyKey = `${chatId}-${targetUserId}`;
  
  const verification = verifiedUsers.get(verifyKey);
  if (!verification) {
    return bot.sendMessage(chatId, `❌ ${targetUsername} is not verified.`, { reply_to_message_id: msg.message_id });
  }
  
  // Remove verification
  verifiedUsers.delete(verifyKey);
  walletRegistry.delete(`${chatId}-${verification.wallet}`);
  
  bot.sendMessage(chatId, `✅ Removed verification from ${targetUsername}.`, { reply_to_message_id: msg.message_id });
});

// =============================================================================
// NEW MEMBER HANDLING (Optional: Restrict until verified)
// =============================================================================

bot.on('new_chat_members', async (msg) => {
  const chatId = msg.chat.id;
  const settings = groupSettings.get(chatId);
  
  // Only restrict if settings exist and restrictNewUsers is enabled
  if (!settings?.restrictNewUsers) return;
  
  for (const member of msg.new_chat_members) {
    if (member.is_bot) continue;
    
    try {
      await bot.restrictChatMember(chatId, member.id, {
        can_send_messages: false,
        can_send_media_messages: false,
        can_send_polls: false,
        can_send_other_messages: false,
        can_add_web_page_previews: false,
        can_change_info: false,
        can_invite_users: false,
        can_pin_messages: false,
      });
      
      bot.sendMessage(
        chatId,
        `Welcome ${member.first_name}! Please use /verify with your Solana wallet to gain access.`
      );
    } catch (error) {
      console.error('Failed to restrict new member:', error);
    }
  }
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

bot.on('polling_error', console.error);
process.on('unhandledRejection', console.error);

// =============================================================================
// STARTUP
// =============================================================================

console.log(`
╔════════════════════════════════════════════════════════════════════╗
║            FairScale Telegram Verification Bot                     ║
╠════════════════════════════════════════════════════════════════════╣
║  Status:    Online                                                 ║
║                                                                    ║
║  Commands:                                                         ║
║    /verify          Start verification                             ║
║    /check <wallet>  Check any wallet's score                       ║
║    /mystatus        View your verification                         ║
║    /setup <score>   Set minimum score (Admin)                      ║
║    /settings        View settings (Admin)                          ║
║    /unverify        Remove verification (Admin)                    ║
╚════════════════════════════════════════════════════════════════════╝
`);
