'use strict';
const crypto = require('node:crypto');
const { db, trackEvent } = require('../db');

const SESSION_DAYS = 30;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

function createUser(email, password) {
  const normalized = String(email).trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)) throw new Error('invalid email');
  if (String(password).length < 8) throw new Error('password must be at least 8 characters');
  const ingestToken = crypto.randomBytes(20).toString('hex');
  const { lastInsertRowid } = db
    .prepare('INSERT INTO users (email, password_hash, ingest_token) VALUES (?, ?, ?)')
    .run(normalized, hashPassword(password), ingestToken);
  trackEvent('signup', { userId: Number(lastInsertRowid) });
  return Number(lastInsertRowid);
}

function authenticate(email, password) {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).trim().toLowerCase());
  if (!user || !verifyPassword(password, user.password_hash)) return null;
  return user;
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_DAYS * 86400_000).toISOString();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expires);
  return token;
}

function destroySession(token) {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

function getSessionUser(token) {
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token = ? AND s.expires_at > datetime('now')`
    )
    .get(token);
  return row || null;
}

// Express middleware: attaches req.user or redirects to /login.
function requireLogin(req, res, next) {
  const user = getSessionUser(req.cookies.session);
  if (!user) return res.redirect('/login');
  req.user = user;
  next();
}

module.exports = { createUser, authenticate, createSession, destroySession, getSessionUser, requireLogin, hashPassword, verifyPassword };
