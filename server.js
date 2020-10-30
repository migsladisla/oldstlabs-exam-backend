'use strict';

require('dotenv').config()

const port = parseInt(process.env.PORT || 8010);
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');
const schemas = require('./src/models/index');

db.serialize(() => {
    Object.keys(schemas).forEach(idx => {
        db.run(schemas[idx], (err) => {
            if (err) console.error(err);
        });
    });

    const app = require('./src/app')(db);

    app.listen(port, () => console.log(`App started and listening on port ${port}`));
});
