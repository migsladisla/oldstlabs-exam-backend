const rateLimit = require('express-rate-limit');

const rateLimiter = rateLimit({
	windowMs: 60 * 60 * 1000 * 24, // 1 day window
	max: 5 // start blocking after 5 requests
});

module.exports = rateLimiter;