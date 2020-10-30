sendRefreshToken = (res, token) => {
    // Set refresh token to cookie
    res.cookie('jid', token, {
        httpOnly: true, // For security
        path: '/api/refresh_token' // Automatically set the req cookie in this route
    });
};

module.exports = sendRefreshToken;