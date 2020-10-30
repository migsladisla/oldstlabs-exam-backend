const jwt = require('jsonwebtoken');

const generateAccessToken = (payload) => {
    return jwt.sign({ userId: payload.user_id }, process.env.ACCESS_TOKEN_SECRET, { 
        expiresIn: '15s' 
    });
}

const generateRefreshToken = (payload) => {
    return jwt.sign({ userId: payload.user_id, tokenVersion: payload.token_version }, process.env.REFRESH_TOKEN_SECRET, { 
        expiresIn: '7d' 
    });
}

const verifyToken = (req, res, next) => {
    const authorization = req.headers['authorization'];

    if (!authorization) {
        return res.sendStatus(401);
    }

    try {
        // Verify the access token
        const bearerToken = authorization.split(' ')[1];
        const payload = jwt.verify(bearerToken, process.env.ACCESS_TOKEN_SECRET);
        req.payload = payload;
        next();
    } catch (err) {
        return res.sendStatus(401);
    }
}

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    verifyToken
}