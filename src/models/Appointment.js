const Appointment = `
    CREATE TABLE appointments
    (
        appointment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        comments TEXT NOT NULL,
        appointment_start_date DATETIME default CURRENT_TIMESTAMP,
        appointment_end_date DATETIME default CURRENT_TIMESTAMP,
        created DATETIME default CURRENT_TIMESTAMP,
        CONSTRAINT fk_users
            FOREIGN KEY (user_id)
                REFERENCES roles(user_id)
                    ON DELETE CASCADE
    );
`;

module.exports = Appointment;