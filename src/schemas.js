'use strict';

module.exports = (db) => {
    const createSchema = `
        CREATE TABLE users
        (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            token_version INTEGER DEFAULT 0
        );

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
        )
    `;

    db.exec(createSchema, (err) => {
        if (err) console.error(err);
        console.log('Tables created..');
    });

    return db;
};
