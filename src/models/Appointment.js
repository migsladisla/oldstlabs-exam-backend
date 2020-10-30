const Appointment = `
    CREATE TABLE appointments
    (
        appointment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        comments TEXT NOT NULL,
        start_date DATETIME default TEXT,
        end_date DATETIME default TEXT,
        created DATETIME default CURRENT_TIMESTAMP,
        CONSTRAINT fk_users
            FOREIGN KEY (user_id)
                REFERENCES roles(user_id)
                    ON DELETE CASCADE
    );
`;

module.exports = Appointment;