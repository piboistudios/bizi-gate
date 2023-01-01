const tls = require('tls');
const fs = require('fs');
const server = tls.createServer({
    key: fs.readFileSync('./keys/spdy-key.pem'),
    cert: fs.readFileSync('./keys/spdy-cert.pem')
});

server.on('connection', s => {
    console.log("Encrypted?", s.encrypted);
});
server.listen(9119);