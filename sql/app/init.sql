CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45),
    url VARCHAR(255),
    request TEXT,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    label INTEGER,
    confidence FLOAT
); 