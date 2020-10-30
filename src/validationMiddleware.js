const { body, query } = require('express-validator');

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
                query('start').optional().isISO8601().withMessage('Date must be in ISO 8601 format'),
                query('end').optional().isISO8601().withMessage('Date must be in ISO 8601 format')
            ]
        }
        case 'createAppointment': {
            return [
                body('user_id').isInt().withMessage('user_id must be a number'),
                body('comments').not().isEmpty().isLength({ max: 250 }).withMessage('Comment is 250 characters max'),
                body('start_date').isISO8601().withMessage('Date must be in ISO 8601 format'),
                body('end_date').isISO8601().withMessage('Date must be in ISO 8601 format')
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