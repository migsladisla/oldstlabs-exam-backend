'use strict';

const express = require('express');
const cors = require('cors')
const app = express();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sendRefreshToken = require('./jwt/sendRefreshToken');
const validateRequest = require('./validationMiddleware');
const { validationResult } = require('express-validator');
const { generateAccessToken, generateRefreshToken, verifyToken } = require('./jwt/auth');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors())

const routes = db => {
    app.post('/api/refresh_token', (req, res) => {
        // Check the refresh token stored in the req cookie
        const { refreshToken } = req.body; // For seprate client

        // For postman
        // const refreshToken = req.cookies.jid;

        if (!refreshToken) return res.sendStatus(401);

        // Verify refresh token
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
            if (err) return res.sendStatus(403);

            db.all('SELECT user_id, token_version FROM users WHERE user_id = ?', decoded.userId, (err, user) => {
                if (err) return res.sendStatus(500);

                // Create new refresh token
                const newRefreshToken = generateRefreshToken(user[0]);
                sendRefreshToken(res, newRefreshToken);
                const newAccessToken = generateAccessToken(user[0]);

                return res.json({ 
                    accessToken: newAccessToken,
                    refreshToken: newRefreshToken
                });
            });
        });
    });

    app.post('/api/register', validateRequest('register'), (req, res) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const saltRounds = 10;
        const { first_name, last_name, password, email } = req.body;

        // Check if email exists
        db.all('SELECT email FROM users WHERE email = ?', email, (err, user) => {
            if (err) return res.sendStatus(500);

            if (user.length > 0) {
                return res.status(409).json({
                    message: `Email ${user[0].email} is already taken`
                });
            }

            // Hash pw
            bcrypt.hash(password, saltRounds).then((hashedPassword) => {
                const userCredentials = [
                    first_name,
                    last_name,
                    email,
                    hashedPassword
                ];
                
                // Register user
                db.run('INSERT INTO users (first_name, last_name, email, password) \
                    VALUES (?, ?, ?, ?)', userCredentials, (err) => {
                        if (err) return res.sendStatus(500);
            
                        return res.json({
                            message: 'Successfully registered' 
                        });
                });
            });
        });
    });

    app.post('/api/login', validateRequest('login'), (req, res) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        db.all('SELECT user_id, password, token_version FROM users WHERE email = ?', email, async (err, user) => {
            if (err) return res.sendStatus(500);

            if (user.length === 0) {
                return res.status(400).json({
                    message: 'Invalid credentials'
                });
            }

            // Compare req pw to hashed pw
            const hashPassword = user[0].password;
            const match = await bcrypt.compare(password, hashPassword);

            if (!match) {
                return res.status(401).json({
                    message: 'Incorrect password'
                });
            }
            
            // Generate access token valid for 15m
            const accessToken = generateAccessToken(user[0]);
            const refreshToken = generateRefreshToken(user[0]);

            // Generate refresh token valid for 7d
            sendRefreshToken(res, refreshToken);

            return res.json({
                message: 'Logged in successfully',
                accessToken,
                refreshToken
            });
        });
    });

    app.delete('/api/logout', (req, res) => {
        sendRefreshToken(res, '');
        res.sendStatus(204);
    });

    app.get('/api/appointments', (req, res) => {
        db.all('SELECT * FROM appointments', (err, appointments) => {
            if (err) return res.sendStatus(500);

            return res.json(appointments);
        });
    });

    app.get('/api/profile/appointments', 
        verifyToken,
        validateRequest('userAppointments'),
        (req, res) => {
            const errors = validationResult(req);
    
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            let { start, end } = req.query;

            if (typeof start !== 'undefined' && typeof end !== 'undefined') {
                const range = [start, end, req.payload.userId];

                db.all('SELECT * FROM appointments WHERE start_date >= ? AND end_date <= ? \
                    AND user_id = ?', 
                    range, 
                    (err, appointments) => {
                        if (err) return res.sendStatus(500);
        
                        return res.json(appointments);
                });
            } else {
                db.all('SELECT * FROM appointments', (err, appointments) => {
                    if (err) return res.sendStatus(500);
    
                    return res.json(appointments);
                });
            }
    });

    app.get('/api/appointment/:id',
        verifyToken,
        (req, res) => {
            const values = [req.params.id, req.payload.userId];

            db.all('SELECT * FROM appointments WHERE appointment_id = ? AND user_id = ?', 
                values, 
                (err, appointment) => {
                    if (err) return res.sendStatus(500);

                    return res.json(appointment);
            });
    });

    app.post('/api/appointment', 
        verifyToken,
        validateRequest('createAppointment'), 
        (req, res) => {
            const errors = validationResult(req);
    
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const { comments, start_date, end_date } = req.body;
            const values = [
                req.payload.userId,
                comments,
                start_date.replace('T', ' '),
                end_date.replace('T', ' ')
            ];

            db.run('INSERT INTO appointments (user_id, comments, start_date, end_date) \
                VALUES (?, ?, ?, ?)', values, (err) => {
                    if (err) return res.sendStatus(500);

                    return res.json({ message: 'Successfully booked an appointment' });
            });
    });

    app.put('/api/appointment/:id', 
        verifyToken, 
        validateRequest('editAppointment'),
        (req, res) => {
            const errors = validationResult(req);
    
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const requestId = req.params.id;
            const { comments, start_date, end_date } = req.body;

            db.all('SELECT * FROM appointments WHERE appointment_id = ?', requestId, (err, appointment) => {
                if (err) return res.sendStatus(500);

                if (appointment.length === 0) {
                    return res.status(404).json({
                        message: 'Appointment not found'
                    });
                }

                const values = [
                    comments,
                    start_date,
                    end_date,
                    requestId
                ];

                db.run('UPDATE appointments SET comments = ?, start_date = ?, end_date = ? \
                    WHERE appointment_id = ?', values, (err) => {
                    if (err) res.sendStatus(500);

                    db.all('SELECT appointment_id, comments, start_date, end_date \
                        FROM appointments', (err, appointment) => {
                            if (err) return res.sendStatus(500);
                
                            return res.json(appointment[0]);
                    });
                });
            });
    });

    app.delete('/api/appointment/:id', 
        verifyToken,
        (req, res) => {
            const errors = validationResult(req);
    
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
            
            const requestId = req.params.id;

            db.all('DELETE FROM appointments WHERE appointment_id = ?', requestId, (err, appointment) => {
                if (err) return res.sendStatus(500);
                
                return res.json({ message: 'Appointment deleted'});
            });
    });

    return app;
}

module.exports = routes;