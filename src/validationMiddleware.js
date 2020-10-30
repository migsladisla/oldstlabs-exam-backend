const { body } = require('express-validator');

const validateRequest = (method) => {
    switch (method) {
        case 'register': {
            return [
                body('first_name', 'First name must be 2-30 characters long').isLength({ min: 2, max: 30 }),
                body('last_name', 'Last name must be 2-30 characters long').isLength({ min: 2, max: 30 }),
                body('email', 'Email must be a valid email address').isEmail(),
                body('password', 'Password must be atleast 6 characters long').isLength({ min: 6 })
            ]
        }
        case 'login': {
            return [
                body('email', 'Email must be a valid email address').isEmail(),
                body('password', 'Password must be atleast 6 characters long').isLength({ min: 6 })
            ]
        }
        case 'createAppointment': {
            return [
                body('user_id').isInt(),
                body('comments').not().isEmpty().isLength({ max: 250 })
            ]
        }
        case 'editAppointment': {
            return [
                body('comments').not().isEmpty().isLength({ max: 250 })
            ]
        }
        case 'deleteAppointment': {
            return [
                body('user_id').isInt()
            ]
        }
    }
}

module.exports = validateRequest;