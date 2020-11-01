const { body, query } = require('express-validator');
const moment = require('moment');

const validateRequest = (method) => {
    switch (method) {
        case 'register': {
            return [
                body('first_name').isLength({ min: 2, max: 30 }).withMessage('First name must be 2-30 characters long'),
                body('last_name').isLength({ min: 2, max: 30 }).withMessage('Last name must be 2-30 characters long'),
                body('email').isEmail().withMessage('Email must be a valid email address'),
                body('password').isLength({ min: 6 }).withMessage('Password must be atleast 6 characters long')
            ]
        }
        case 'login': {
            return [
                body('email').isEmail().withMessage('Email must be a valid email address'),
                body('password').isLength({ min: 6 }).withMessage('Password must be atleast 6 characters long')
            ]
        }
        case 'userAppointments': {
            return [
                query('start').optional().custom(value => {
                    if (!moment(value, "YYYY-MM-DD", true).isValid()) {
                        throw new Error('Date must be in yyyy-mm-dd format');
                    }
                    
                    return true;
                }),
                query('end').optional().custom(value => {
                    if (!moment(value, "YYYY-MM-DD", true).isValid()) {
                        throw new Error('Date must be in yyyy-mm-dd format');
                    }
                    
                    return true;
                })
            ]
        }
        case 'createAppointment': {
            return [
                body('user_id').isInt().withMessage('user_id must be a number'),
                body('comments').not().isEmpty().isLength({ max: 250 }).withMessage('Comment is 250 characters max'),
                body('start_date').custom(value => {
                    if (!moment(value, "YYYY-MM-DDTHH:mm:ss", true).isValid()) {
                        throw new Error('Date must be in ISO 8601 format');
                    }
                    
                    return true;
                }),
                body('end_date').custom(value => {
                    if (!moment(value, "YYYY-MM-DDTHH:mm:ss", true).isValid()) {
                        throw new Error('Date must be in ISO 8601 format');
                    }
                    
                    return true;
                })
            ]
        }
        case 'editAppointment': {
            return [
                body('comments').not().isEmpty().isLength({ max: 250 }).withMessage('Comment is 250 characters max')
            ]
        }
        case 'deleteAppointment': {
            return [
                body('user_id').isInt().withMessage('user_id must be a number')
            ]
        }
    }
}

module.exports = validateRequest;