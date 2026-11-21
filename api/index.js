// Vercel entry point — Vercel runs this as a serverless function and forwards every request to the Express app.
// On cPanel / VPS this file is not used: start the site with `npm start` (server.js).
module.exports = require('../server.js');
