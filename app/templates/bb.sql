CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name TEXT NOT NULL,username TEXT NOT NULL, email TEXT NOT NULL UNIQUE, phone TEXT VARCHAR(20) NOT NULL UNIQUE, dob TEXT NOT NULL, hash TEXT NOT NULL);


CREATE TABLE sqlite_sequence(name,seq);

CREATE UNIQUE INDEX username ON users (username);


CREATE TABLE birthdays (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT , phone TEXT, birthdates DATE NOT NULL, user_id INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id));


"INSERT INTO birthdays(user_id, name, birthdate,phone, email) VALUES(?, ?, ?, ?, ?)", session['user_id'], name, birthdate,phone, email

"DELETE FROM birthdays WHERE id=? AND user_id= ?", id, session['user_id']

"SELECT * FROM users WHERE id = ?", session["user_id"]


CREATE TABLE audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, action TEXT NOT NULL, timestamp DATETIME NOT NULL, FOREIGN KEY (user_id) REFERENCES users (id));

