# NadRacer Server - Rate Limiting & Anti-Cheat Configuration

This document explains the configurable rate limiting and anti-cheat settings for the NadRacer server.

## 🔒 **Environment Variables Overview**

All rate limiting and validation settings can now be controlled through environment variables in your `.env` file. This allows you to easily adjust limits for different environments (development, staging, production) without modifying code.

## 📊 **Rate Limiting Settings**

### **General API Rate Limiting**
Controls overall API access to prevent abuse:

```bash
RATE_LIMIT_GENERAL_WINDOW_MS=900000    # Time window in milliseconds (15 minutes)
RATE_LIMIT_GENERAL_MAX=100             # Max requests per window per IP
```

### **Score Submission Rate Limiting**
Specific limits for score submission endpoints:

```bash
RATE_LIMIT_SCORE_WINDOW_MS=60000       # Time window (1 minute)
RATE_LIMIT_SCORE_MAX=10                # Max score submissions per window per IP
```

## 🎯 **Score Validation Limits**

### **Maximum Values**
```bash
MAX_SCORE_LIMIT=1000000                # Absolute maximum score allowed
MAX_TRANSACTIONS_LIMIT=10000           # Maximum transactions count allowed
MAX_REASONABLE_SCORE=10000             # Scores above this are rejected as invalid
SUSPICIOUS_SCORE_THRESHOLD=100000      # Scores above this trigger warnings
```

### **Anti-Cheat Logic**
- **Reasonable Score**: Scores above `MAX_REASONABLE_SCORE` are immediately rejected
- **Suspicious Threshold**: Scores above `SUSPICIOUS_SCORE_THRESHOLD` with only 1 transaction are logged as suspicious
- **Maximum Limits**: Hard caps on score and transaction values

## 👤 **Per-Wallet Rate Limiting**

Prevents individual wallets from spamming submissions:

```bash
WALLET_SUBMISSIONS_PER_HOUR=20         # Max submissions per wallet per hour
WALLET_RATE_RESET_MS=3600000           # Rate limit reset window (1 hour)
```

## ⏰ **Session Management**

Controls game session lifetime and cleanup:

```bash
MAX_SESSION_AGE_MS=1800000             # Max game session duration (30 minutes)
SESSION_CLEANUP_AGE_MS=3600000         # Clean up old sessions (1 hour)
```

## 🌍 **Environment-Specific Configurations**

### **Development Settings** (Current `.env`)
More permissive limits for testing:
- `RATE_LIMIT_GENERAL_MAX=200` (higher than production)
- `RATE_LIMIT_SCORE_MAX=20` (higher than production)
- `MAX_REASONABLE_SCORE=50000` (higher for testing)
- `WALLET_SUBMISSIONS_PER_HOUR=50` (more frequent testing)

### **Production Settings** (Recommended)
Stricter limits for security:
- `RATE_LIMIT_GENERAL_MAX=100`
- `RATE_LIMIT_SCORE_MAX=10`
- `MAX_REASONABLE_SCORE=10000`
- `WALLET_SUBMISSIONS_PER_HOUR=20`

## 🚀 **Quick Configuration Examples**

### **For Load Testing**
```bash
RATE_LIMIT_GENERAL_MAX=1000
RATE_LIMIT_SCORE_MAX=100
WALLET_SUBMISSIONS_PER_HOUR=100
MAX_REASONABLE_SCORE=100000
```

### **For Strict Production**
```bash
RATE_LIMIT_GENERAL_MAX=50
RATE_LIMIT_SCORE_MAX=5
WALLET_SUBMISSIONS_PER_HOUR=10
MAX_REASONABLE_SCORE=5000
```

### **For Development**
```bash
RATE_LIMIT_GENERAL_MAX=500
RATE_LIMIT_SCORE_MAX=50
WALLET_SUBMISSIONS_PER_HOUR=100
MAX_REASONABLE_SCORE=50000
```

## ⚡ **Server Startup Logging**

When you start the server, it will display the current configuration:

```
🔒 Security Configuration:
   General Rate Limit: 200 requests/900s
   Score Rate Limit: 20 submissions/60s
   Wallet Rate Limit: 50 submissions/60min
   Max Score: 1,000,000
   Max Reasonable Score: 50,000
   Session Max Age: 30min
```

## 🛠 **How to Change Limits**

1. **Edit your `.env` file** in the server directory
2. **Update the desired variables**
3. **Restart the server** for changes to take effect
4. **Check the startup logs** to verify new settings

Example:
```bash
# Increase score submission limit for testing
RATE_LIMIT_SCORE_MAX=30
MAX_REASONABLE_SCORE=75000

# Then restart server
npm start
```

## ⚠️ **Important Notes**

- **Time values** are in milliseconds (1000ms = 1 second)
- **All limits default** to safe production values if not specified
- **Server restart required** for changes to take effect
- **Monitor logs** for rate limiting events during testing
- **Production values** should be more restrictive than development

## 📈 **Monitoring Rate Limits**

The server logs when rate limits are triggered:

- `🚫 CORS blocked request from: origin` - CORS violations
- `🚫 Rate limit exceeded for wallet: address` - Wallet rate limit hit
- `⚠️ Suspicious score submission: score points` - Suspicious activity
- `😫 Suspiciously high score: score from address` - Score validation failure

## 🔍 **Troubleshooting**

**Problem**: Score submissions failing with "Score appears to be invalid"
**Solution**: Increase `MAX_REASONABLE_SCORE` in your `.env`

**Problem**: "Too many score submissions" error
**Solution**: Increase `RATE_LIMIT_SCORE_MAX` or `WALLET_SUBMISSIONS_PER_HOUR`

**Problem**: "Game session has expired"
**Solution**: Increase `MAX_SESSION_AGE_MS`