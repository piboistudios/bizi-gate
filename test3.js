const dgram = require('dgram')
  ; const address = '239.1.2.3'
const port = 5554
const net = require('net');

let socket = dgram.createSocket({
  type: 'udp4',
  reuseAddr: true // for testing multiple instances on localhost
})

socket.bind(port)


net.createServer().listen(port);

socket.on('message', (msg, remote) => {
  console.log(msg.toString().trim())
})
// socket.addm
socket.on("listening", function () {
  // this.setBroadcast(true)
  // this.setMulticastTTL(128)
  // this.addMembership(address)
  // console.log('Multicast listening . . . ')
})

// setInterval(()=>{
  // let message = 'Hi! ' + new Date().getTime() + process.argv.slice(2);
  // socket.send(message, 0, message.length, port, address)
// }, 500)
