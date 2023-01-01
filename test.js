const http = require('http');
const express = require('express');
const app = express();
const app2 = express();
app2.get("/", (req, res) => {
    res.status(200).json("Welcome to the other server!");
})
app.get("/", (req, res) => {

    if (req.socket.handled) {
        console.log("Request handled already, hanging");
        return;
    }
    console.log("Handling");
    res.status(200).json("OK");
})
const net = require('net');
const srv = net.createServer();
const stream = require('stream');
const { Duplex, PassThrough } = require('stream');
srv.on('connection', s => {

    s.once('data', d => {
        // s.emit('data', d);
        if (d.indexOf('other-server') !== -1) {
            console.log("routing to other server");
            s.handled = true;
            otherServer.emit('connection', s);
        } else {
            downstreamServer.emit('connection', s);
        }
        s.emit('data', d);
    });

});

srv.listen(9191);

const otherServer = http.createServer(app2);
otherServer.on('connection', s => {
    console.log("connect?");
    s.on('data', d => {
        console.log('other server data:', '' + d);
    });
})
const downstreamServer = http.createServer(app);