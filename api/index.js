// Vercel entry point — Vercel runs this as a serverless function and forwards every request to the Express app.
// On cPanel / VPS this file is not used: start the site with `npm start` (server.js).
let app;
let startupError = null;
try {
  app = require('../server.js');
} catch (err) {
  startupError = err;
  console.error('[startup] SDS failed to start:', err);
}

module.exports = (req, res) => {
  if (app) return app(req, res);
  // Show only the error message (no stack trace) so the cause is visible during testing.
  res.statusCode = 500;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end(`SDS failed to start on Vercel.\nNode ${process.version}\n${startupError && startupError.code ? startupError.code + ': ' : ''}${startupError && startupError.message}`);
};
