'use strict';

const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const secret = process.env.SECRET_KEY;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const verifyToken = (req, res, next) => {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearerToken = bearerHeader.split(' ')[1];
        req.token = bearerToken;
        next();
    } else {
        res.sendStatus(401);
    }
}

module.exports = (db) => {
    app.post('/login', (req, res) => {
        const creds = [
            req.body.email,
            req.body.password
        ];

        db.all('SELECT * FROM users WHERE email = ? and password = ?', creds, (err, user) => {
            if (err) console.error(err);

            if (user.length === 0) {
                res.status(401).json({
                    message: 'Invalid credentials'
                });
            } else {
                jwt.sign({ user: user[0] }, secret, { expiresIn: '1800s' }, (err, token) => {
                    res.status(200).json({ 
                        message: 'Logged in successfully',
                        token 
                    });
                });
            }
        });
    });

    app.post('/register', (req, res) => {
        const values = [
            req.body.first_name,
            req.body.last_name,
            req.body.email,
            req.body.password
        ];

        db.run('INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)', values, (err) => {
            if (err) res.send(err);

            res.status(200).json({ 
                message: 'Successfully registered' 
            });
        });
    });

    app.get('/appointments', (req, res) => {
        db.all('SELECT * FROM appointments', (err, appointments) => {
            if (err) res.send(err);

            res.status(200).json(appointments);
        });
    });

    app.post('/appointment', verifyToken, (req, res) => {
        var values = [
            req.body.user_id,
            req.body.comments,
            req.body.appointment_start_date, 
            req.body.appointment_end_date
        ];

        db.run('INSERT INTO appointments (user_id, comments, appointment_start_date, appointment_end_date) \
            VALUES (?, ?, ?, ?)', values, (err) => {
                if (err) res.send(err);

                res.status(200).json({ message: 'Successfully booked appointment' });
        });
    });

    app.put('/appointment', verifyToken, (req, res) => {

    });

    app.delete('/appointment', verifyToken, (req, res) => {

    });

    return app;
}