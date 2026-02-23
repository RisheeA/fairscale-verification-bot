// FairScale Telegram Verification Bot
// Production-ready with wallet ownership verification

import TelegramBot from 'node-telegram-bot-api';
import { Connection, PublicKey } from '@solana/web3.js';
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
  
  // Verification
  TREASURY_WALLET: process.env.TREASURY_WALLET || 'fairAUEuR1SCcHL254Vb3F3XpUWLruJ2a11f6QfANEN',
  VERIFICATION_AMOUNT_SOL: 0.001, // 0.001 SOL to verify ownership
  VERIFICATION_AMOUNT_LAMPORTS: 1000000, // 0.001 SOL in lamports
  
  // Solana
  SOLANA_RPC: process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com',
  
  // Defaults
  DEFAULT_MIN_SCORE: 60,
  
  // Rate limiting
  VERIFY_COOLDOWN_MS: 60 * 1000,
  MAX_ATTEMPTS_PER_HOUR: 5,
  
  // Verification timeout
  VERIFICATION_TIMEOUT_MS: 10 * 60 * 1000, // 10 minutes to complete verification
};

// Initialize Solana connection
const solana = new Connection(CONFIG.SOLANA_RPC, 'confirmed');

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

// Pending verifications: `${chatId}-${userId}` -> { state, wallet, timestamp, verificationCode }
const pendingVerifications = new Map();

// Admin cache: chatId -> Set of admin userIds
const adminCache = new Map();

// Processed transactions (prevent replay)
const processedTxs = new Set();

// =============================================================================
// HELPERS
// =============================================================================

function isValidSolanaAddress(address) {
  if (!address || typeof address !== 'string') return false;
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
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

async function verifyWalletPayment(wallet) {
  try {
    const walletPubkey = new PublicKey(wallet);
    const treasuryPubkey = new PublicKey(CONFIG.TREASURY_WALLET);
    
    // Get recent transactions for the wallet
    const signatures = await solana.getSignaturesForAddress(walletPubkey, { limit: 10 });
    
    for (const sigInfo of signatures) {
      // Skip if already processed
      if (processedTxs.has(sigInfo.signature)) continue;
      
      // Skip if older than verification timeout
      if (sigInfo.blockTime && Date.now() - sigInfo.blockTime * 1000 > CONFIG.VERIFICATION_TIMEOUT_MS) {
        continue;
      }
      
      // Get transaction details
      const tx = await solana.getTransaction(sigInfo.signature, {
        commitment: 'confirmed',
        maxSupportedTransactionVersion: 0,
      });
      
      if (!tx || tx.meta?.err) continue;
      
      // Check if it's a transfer to our treasury
      const preBalances = tx.meta.preBalances;
      const postBalances = tx.meta.postBalances;
      const accountKeys = tx.transaction.message.staticAccountKeys || tx.transaction.message.accountKeys;
      
      for (let i = 0; i < accountKeys.length; i++) {
        const account = accountKeys[i].toString();
        
        if (account === CONFIG.TREASURY_WALLET) {
          const received = postBalances[i] - preBalances[i];
          
          if (received >= CONFIG.VERIFICATION_AMOUNT_LAMPORTS) {
            // Verify sender is the wallet claiming ownership
            const senderIndex = tx.transaction.message.staticAccountKeys ? 0 : 0;
            const sender = accountKeys[senderIndex].toString();
            
            if (sender === wallet) {
              // Mark as processed
              processedTxs.add(sigInfo.signature);
              return { verified: true, signature: sigInfo.signature };
            }
          }
        }
      }
    }
    
    return { verified: false };
  } catch (error) {
    console.error('Verification error:', error);
    return { verified: false, error: error.message };
  }
}

async function isAdmin(bot, chatId, userId) {
  try {
    if (adminCache.has(chatId)) {
      return adminCache.get(chatId).has(userId);
    }
    
    const admins = await bot.getChatAdministrators(chatId);
    const adminSet = new Set(admins.map(a => a.user.id));
    adminCache.set(chatId, adminSet);
    
    setTimeout(() => adminCache.delete(chatId), 5 * 60 * 1000);
    
    return adminSet.has(userId);
  } catch (error) {
    console.error('Failed to check admin status:', error);
    return false;
  }
}

function formatScore(data, passed, minScore) {
  const status = passed ? '✅ VERIFIED' : '❌ NOT VERIFIED';
  
  let message = `*FairScale Verification*\n\n`;
  message += `${status}\n\n`;
  message += `*FairScore:* ${data.fairscore}/100\n`;
  message += `*Required:* ${minScore}+\n`;
  
  if (!passed) {
    message += `\n_You need a score of ${minScore} or higher to verify._`;
  }
  
  return message;
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
    message += `/setup <score> - Set minimum score\n`;
    message += `/restrict - Toggle restrict mode (block unverified users)\n`;
    message += `/settings - View current settings\n`;
    message += `/unverify - Remove user verification (reply to user)`;
  } else {
    message = `*⚖️ FairScale Verification Bot*\n\n`;
    message += `Add me to a group to enable wallet-based verification.\n\n`;
    message += `*How it works:*\n`;
    message += `1. Add bot to your group\n`;
    message += `2. Make bot admin\n`;
    message += `3. Use /setup to set minimum score\n`;
    message += `4. Use /restrict to block unverified users\n`;
    message += `5. Users verify with /verify`;
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
  
  // Set pending state - awaiting wallet
  pendingVerifications.set(verifyKey, { 
    state: 'awaiting_wallet', 
    timestamp: Date.now() 
  });
  
  bot.sendMessage(
    chatId,
    `*Step 1/2:* Please reply with your Solana wallet address.`,
    { parse_mode: 'Markdown', reply_to_message_id: msg.message_id }
  );
});

// =============================================================================
// COMMAND: /confirm
// =============================================================================

bot.onText(/\/confirm/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const verifyKey = `${chatId}-${userId}`;
  
  const pending = pendingVerifications.get(verifyKey);
  
  if (!pending || pending.state !== 'awaiting_payment') {
    return bot.sendMessage(
      chatId,
      '❌ No pending verification. Use /verify to start.',
      { reply_to_message_id: msg.message_id }
    );
  }
  
  // Check timeout
  if (Date.now() - pending.timestamp > CONFIG.VERIFICATION_TIMEOUT_MS) {
    pendingVerifications.delete(verifyKey);
    return bot.sendMessage(
      chatId,
      '❌ Verification expired. Please start again with /verify.',
      { reply_to_message_id: msg.message_id }
    );
  }
  
  const loadingMsg = await bot.sendMessage(
    chatId,
    '⏳ Checking for payment...',
    { reply_to_message_id: msg.message_id }
  );
  
  // Verify payment from wallet
  const verification = await verifyWalletPayment(pending.wallet);
  
  if (!verification.verified) {
    return bot.editMessageText(
      `❌ Payment not found.\n\nMake sure you sent *exactly ${CONFIG.VERIFICATION_AMOUNT_SOL} SOL* from:\n\`${pending.wallet}\`\n\nTo:\n\`${CONFIG.TREASURY_WALLET}\`\n\nThen try /confirm again.`,
      { 
        chat_id: chatId, 
        message_id: loadingMsg.message_id,
        parse_mode: 'Markdown'
      }
    );
  }
  
  // Payment verified - now check FairScore
  recordAttempt(chatId, userId);
  
  const settings = groupSettings.get(chatId) || { minScore: CONFIG.DEFAULT_MIN_SCORE };
  const data = await getFairScore(pending.wallet);
  
  if (!data || data.fairscore === undefined) {
    pendingVerifications.delete(verifyKey);
    return bot.editMessageText(
      '❌ Failed to fetch wallet score. Please try again later.',
      { chat_id: chatId, message_id: loadingMsg.message_id }
    );
  }
  
  const passed = data.fairscore >= settings.minScore;
  
  if (passed) {
    // Store verification
    verifiedUsers.set(verifyKey, {
      wallet: pending.wallet,
      score: data.fairscore,
      verifiedAt: new Date().toISOString(),
      txSignature: verification.signature,
    });
    walletRegistry.set(`${chatId}-${pending.wallet}`, { userId });
    
    // Unrestrict user
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
      // Bot may not have permission
    }
  }
  
  pendingVerifications.delete(verifyKey);
  
  const message = formatScore(data, passed, settings.minScore);
  
  bot.editMessageText(message, {
    chat_id: chatId,
    message_id: loadingMsg.message_id,
    parse_mode: 'Markdown',
  });
});

// =============================================================================
// HANDLE WALLET SUBMISSION
// =============================================================================

bot.on('message', async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const text = msg.text;
  
  if (!text || text.startsWith('/')) return;
  
  const verifyKey = `${chatId}-${userId}`;
  const pending = pendingVerifications.get(verifyKey);
  
  if (!pending || pending.state !== 'awaiting_wallet') return;
  
  // Check timeout
  if (Date.now() - pending.timestamp > CONFIG.VERIFICATION_TIMEOUT_MS) {
    pendingVerifications.delete(verifyKey);
    return;
  }
  
  const wallet = text.trim();
  
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
  
  // Update state to awaiting payment
  pendingVerifications.set(verifyKey, {
    state: 'awaiting_payment',
    wallet: wallet,
    timestamp: Date.now(),
  });
  
  const message = `*Step 2/2: Verify Wallet Ownership*\n\n` +
    `Send *exactly ${CONFIG.VERIFICATION_AMOUNT_SOL} SOL* from:\n` +
    `\`${wallet}\`\n\n` +
    `To:\n` +
    `\`${CONFIG.TREASURY_WALLET}\`\n\n` +
    `Once sent, reply with /confirm\n\n` +
    `_This proves you own this wallet. You have 10 minutes._`;
  
  bot.sendMessage(chatId, message, { 
    parse_mode: 'Markdown', 
    reply_to_message_id: msg.message_id 
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
  
  let message = `*⚖️ FairScale Wallet Check*\n\n`;
  message += `*Wallet:* \`${wallet.slice(0, 8)}...${wallet.slice(-6)}\`\n`;
  message += `*FairScore:* ${data.fairscore}/100\n`;
  
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
  
  if (!await isAdmin(bot, chatId, userId)) {
    return bot.sendMessage(chatId, '❌ Only admins can use this command.', { reply_to_message_id: msg.message_id });
  }
  
  if (minScore === null || minScore < 0 || minScore > 100) {
    return bot.sendMessage(chatId, 'Usage: /setup <score>\nExample: /setup 60', { reply_to_message_id: msg.message_id });
  }
  
  const settings = groupSettings.get(chatId) || { minScore: CONFIG.DEFAULT_MIN_SCORE, restrictNewUsers: false };
  settings.minScore = minScore;
  groupSettings.set(chatId, settings);
  
  bot.sendMessage(
    chatId,
    `✅ Minimum FairScore set to ${minScore}`,
    { reply_to_message_id: msg.message_id }
  );
});

// =============================================================================
// COMMAND: /restrict (Admin)
// =============================================================================

bot.onText(/\/restrict/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  
  const isGroup = msg.chat.type === 'group' || msg.chat.type === 'supergroup';
  if (!isGroup) {
    return bot.sendMessage(chatId, '❌ This command only works in groups.');
  }
  
  if (!await isAdmin(bot, chatId, userId)) {
    return bot.sendMessage(chatId, '❌ Only admins can use this command.', { reply_to_message_id: msg.message_id });
  }
  
  const settings = groupSettings.get(chatId) || { minScore: CONFIG.DEFAULT_MIN_SCORE, restrictNewUsers: false };
  settings.restrictNewUsers = !settings.restrictNewUsers;
  groupSettings.set(chatId, settings);
  
  const status = settings.restrictNewUsers ? 'ON' : 'OFF';
  const message = settings.restrictNewUsers 
    ? `🔒 Restrict mode *ON*\n\nNew members will be muted until they verify with /verify.`
    : `🔓 Restrict mode *OFF*\n\nNew members can message without verification.`;
  
  bot.sendMessage(chatId, message, { parse_mode: 'Markdown', reply_to_message_id: msg.message_id });
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
  
  const settings = groupSettings.get(chatId) || { minScore: CONFIG.DEFAULT_MIN_SCORE, restrictNewUsers: false };
  const verifiedCount = Array.from(verifiedUsers.keys()).filter(k => k.startsWith(`${chatId}-`)).length;
  
  const restrictStatus = settings.restrictNewUsers ? '🔒 ON' : '🔓 OFF';
  
  const message = `*⚖️ FairScale Settings*\n\n` +
    `*Minimum Score:* ${settings.minScore}\n` +
    `*Restrict Mode:* ${restrictStatus}\n` +
    `*Verified Users:* ${verifiedCount}\n` +
    `*Verification Fee:* ${CONFIG.VERIFICATION_AMOUNT_SOL} SOL`;
  
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
  
  verifiedUsers.delete(verifyKey);
  walletRegistry.delete(`${chatId}-${verification.wallet}`);
  
  // Re-restrict user if restrict mode is on
  const settings = groupSettings.get(chatId);
  if (settings?.restrictNewUsers) {
    try {
      await bot.restrictChatMember(chatId, targetUserId, {
        can_send_messages: false,
        can_send_media_messages: false,
        can_send_polls: false,
        can_send_other_messages: false,
        can_add_web_page_previews: false,
        can_change_info: false,
        can_invite_users: false,
        can_pin_messages: false,
      });
    } catch (error) {
      // Bot may not have permission
    }
  }
  
  bot.sendMessage(chatId, `✅ Removed verification from ${targetUsername}.`, { reply_to_message_id: msg.message_id });
});

// =============================================================================
// NEW MEMBER HANDLING
// =============================================================================

bot.on('new_chat_members', async (msg) => {
  const chatId = msg.chat.id;
  const settings = groupSettings.get(chatId);
  
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
        `Welcome ${member.first_name}! 👋\n\nThis group requires wallet verification.\n\nUse /verify to get started.`
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
║  Treasury:  ${CONFIG.TREASURY_WALLET}  ║
║  Fee:       ${CONFIG.VERIFICATION_AMOUNT_SOL} SOL                                              ║
║                                                                    ║
║  User Commands:                                                    ║
║    /verify          Start verification                             ║
║    /confirm         Confirm payment sent                           ║
║    /check <wallet>  Check any wallet's score                       ║
║    /mystatus        View your verification                         ║
║                                                                    ║
║  Admin Commands:                                                   ║
║    /setup <score>   Set minimum score                              ║
║    /restrict        Toggle restrict mode                           ║
║    /settings        View settings                                  ║
║    /unverify        Remove verification (reply to user)            ║
╚════════════════════════════════════════════════════════════════════╝
`);
