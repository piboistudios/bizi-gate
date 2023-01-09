const SMTPConnection = require("nodemailer/lib/smtp-connection");
const SMTPServer = require("smtp-server").SMTPServer;
const { mkLogger } = require("./logger");
const { all: allUnbound } = Promise;
const all = allUnbound.bind(Promise);
const http = require('http');
const net = require('net');
const tls = require('tls');
const logger = mkLogger('app');

const DnsZone = require('./models/dns.zone');
const DnsRecordset = require('./models/dns.recordset');
const File = require("./models/file");
const { readFileSync } = require("fs");
const handlers = {};
/**@type {Object.<string, import('net').Server>} */
const servers = {};

async function main() {
    const ports = process.env.PORTS.split(' ') || [];

    const MAX_REGISTRATIONS = 2 ** 16;
    const QuickLRU = (await import('quick-lru')).default;
    /**@type {import('quick-lru').default<string, {key: Buffer, cert: Buffer}>} */
    const keypairs = new QuickLRU({ maxSize: MAX_REGISTRATIONS, maxAge: 1000 * 60 * 5 });
    const Endpoint = require('./models/gate.endpoint');
    const host = process.env.THIS_IP;
    const existingEndpoint = Endpoint.findOne({
        host
    });
    existingEndpoint && await existingEndpoint.remove();
    await new Endpoint({
        ports,
        host
    }).save()

    // t
    /**
     
     * @type {import('quick-lru').default<string, 
     *  import('./types').Model<{
     *      dest: {
     *          host: string,
     *          port: number,
     *          protocol: String,
     *          tlsTermination: Boolean
     *      },
     *      src: {
     *          host: {
     *              stub?: string,
     *              zone?: import('mongoose').Types.ObjectId,
     *          },
     *          port: Number,
     *      },
     *      cn: string,
     *      client?: import('mongoose').Types.ObjectId,
     *      cert?: import('mongoose').Types.ObjectId,
     *      key?: import('mongoose').Types.ObjectId,
     *  }
     * >}
     */
    const registrations = new QuickLRU({ maxSize: MAX_REGISTRATIONS, maxAge: 1000 * 60 * 5 });
    const gateRouter = await require('./gate');
    const thisHosts = [...process.env.THIS_HOST.split(','), 'localhost']


    function parseName(domain) {
        const nameParts = domain.split('.');
        const tld = nameParts.pop();
        const host = nameParts.pop();
        const stub = nameParts.length ? nameParts.join('.') : undefined;
        const zone = [host, tld].filter(Boolean).join('.');
        return { stub, zone };
    }

    function fmtErr() {
        return [...arguments].map(a => {
            if (typeof a === 'string') return a;
            else return JSON.stringify(a);
        }).join('\t');
    }
    const Registration = require('./models/gate.registration');
    const VirtualHost = require('./models/gate.virtual-host');

    async function tryGetRegistration(servername, port) {
        const log = logger.sub('tryGetRegistration');
        const regKey = `${servername}:${port}`;
        if (registrations.has(regKey)) return registrations.get(regKey);
        log.info(servername);
        const { stub, zone } = parseName(servername);
        log.debug({ stub, zone });
        const dnsZone = await DnsZone.findOne({
            dnsName: zone
        });
        if (!dnsZone) throw new Error("No DNS Zone");
        const vHost = await VirtualHost.findOne({
            zone: dnsZone.id,
            stub
        });
        if (!vHost) throw new Error("No Virtual host");
        const registration = await Registration.findOne({
            "src.host": vHost.id,
            "src.port": port,
            protocol: "TCP"
        });
        if (!registration) throw new Error("No port registration");
        !registration.populated('src.host') && await registration.populate('src.host');

        registrations.set(regKey, registration);
        return registration;
    }
    function streamToBuf(stream) {
        const chunks = [];
        return new Promise((resolve, reject) => {
            stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
            stream.on('error', (err) => reject(err));
            stream.on('end', () => resolve(Buffer.concat(chunks)));
        })
    }
    async function tryEnsureKeypair(servername, port) {
        // if (!registrations.has(servername)) return new Error(`No existing registration for: ${servername}`);
        try {

            const registration = await tryGetRegistration(servername, port);//registrations.get(servername);
            /**
             * @type {import('./types').VHost}
             */
            const vHost = registration.src.host;
            const keyFile = await File.findById(vHost.key._id);
            const certFile = await File.findById(vHost.cert._id);
            const key = await streamToBuf(keyFile.read());
            const cert = await streamToBuf(certFile.read());
            keypairs.set(servername, { key, cert })
        } catch (e) {
            return e;
        }
    }
    var selfsigned = require('selfsigned');
    const attrs = [{ name: 'commonName', value: process.env.HOSTNAME }];

    /**@type {import('selfsigned').GenerateResult} */
    const pems = await new Promise((resolve, reject) => selfsigned.generate(attrs, { days: 90 }, (err, pems) => {
        if (err) return reject(err);
        resolve(pems);
    }));
    function mkGateSrv(port, deaf = true) {
        const srv = http.createServer((req, res) => {
            if (thisHosts.includes(req.headers.host)) {
                return gateRouter(req, res)
            }
            res.writeHead(302, {
                location: `https://${req.headers.host}${req.url}`,
            });
            res.end();
        });

        // !deaf && srv.listen(port);
        return srv;
    }

    const gateSrv = mkGateSrv();

    function mkPlainWebServer(port, deaf) {
        logger.info("Starting plain web server on port", port);
        const tlsSrv = mkTlsServer(port, true);
        const srv = net.createServer();
        srv.on('connection', function (socket) {
            socket.once('data', function (data) {
                if (data[0] == 0x16 || data[0] == 0x80 || data[0] == 0x00) {
                    logger.debug('>> TLS detected');
                    tlsSrv.emit('connection', socket);
                } else {
                    logger.debug('>> no TLS detected');
                    gateSrv.emit('connection', socket);
                }
                socket.push(data);
            });
        });
        !deaf && srv.listen(port);

        return srv;

    }
    const pipeTls = async upstream => {
        const downLog = logger.sub('secureConnect:' + upstream.servername + ':' + port + ':' + 'downstream')
        const upLog = logger.sub('secureConnect:' + upstream.servername + ':' + port + ':' + 'upstream')
        upstream.on('error', e => {
            upLog
                .error(e);
        });
        logger.debug("socket servername (SNI):", upstream.servername, upstream.address())
        if (!upstream.servername || thisHosts.indexOf(upstream.servername) !== -1) {
            gateSrv.emit('connection', upstream);
            return;
        }
        const registration = await tryGetRegistration(upstream.servername, port); //registrations.get(upstream.servername + ':' + port);
        if (!registration) {

            upLog.fatal(fmtErr("No registration for: " + upstream.servername + ':' + port));
            return upstream.destroy();
        }
        /**@type {import('./types').VHost} */
        const vHost = registration.src.host;
        if (!vHost) {
            upLog.fatal(fmtErr("No virtual host for: " + upstream.servername));
            return upstream.destroy();
        }
        vHost.populated instanceof Function && !vHost.populated('zone') && await vHost.populate('zone');
        /**@type {import('./types').DnsZone} */
        const dnsZone = vHost.zone;
        if (!dnsZone) {
            upLog.fatal(fmtErr("No DNS Zone found."));
            return upstream.destroy();
        }
        // upstream.au
        const zone = dnsZone.dnsName;
        const stub = vHost.stub;
        const hostname = [stub, zone].filter(Boolean).join('.');
        if (!hostname) {
            return upstream.destroy(fmtErr("Invalid hostname:", { zone, stub, hostname, registration }));
        }
        logger.debug("Attempting to establish downstream connection to", registration.dest.host, "on port", registration.dest.port);
        const proto = registration.dest.tlsTermination ? tls : net;


        let servername;
        if (proto === tls && !net.isIP(registration.dest.host)) servername = registration.dest.host;

        const downstream = proto.connect(registration.dest.port, registration.dest.host, {
            servername,
            rejectUnauthorized: false
        });
        upstream
            .pipe(downstream)
            .pipe(upstream);


        downstream.on('error', e => {
            downLog
                .fatal(e);
            upstream.emit('error', e);
        })
        // sock.on('end', () => {
        //     pipeSock
        // })

    };
    function mkTlsServer(port, deaf) {
        !deaf && logger.info("Starting TLS server on port", port);
        const server = tls.createServer({
            async SNICallback(servername, cb) {
                logger.info("Initiate SNI...", { servername, thisHosts });
                let key, cert;
                if (thisHosts.indexOf(servername) !== -1) {
                    key = pems.private;
                    cert = pems.cert;

                } else {

                    if (!keypairs.has(servername)) {

                        let err = await tryEnsureKeypair(servername, port);
                        logger.fatal("SNI Failure:", err);
                        if (err) return cb(err);
                    }
                    let ctx;
                    const keypair = keypairs.get(servername);
                    key = keypair.key;
                    cert = keypair.cert;
                }
                /** @todo create ctx */
                ctx = tls.createSecureContext({
                    key,
                    cert,
                });
                // ctx.someRandomData = 'foo';
                cb(null, ctx);
            }
        });
        server.on('secureConnection', pipeTls);
        !deaf && server.listen(port);
        return server;

    }

    function mkMailRouter(port) {
        const log = logger.sub("smtp-server");
        log.info("Starting mail router on port", port);
        const srv = new SMTPServer({
            banner: process.env.SMTP_BANNER,
            name: process.env.SMTP_NAME,
            onSecure(socket, session, cb) {
                if (!socket.servername) {
                    log.fatal("SNI failure: no servername provided");
                    return cb(new Error("SNI failure"));
                }
                pipeTls(socket);
            },
            ...Object.fromEntries(['onAuth', 'onMailFrom', 'onRcptTo', 'onData'].map(key => [key, (foo, bar, cb) => {
                cb(new Error("SNI Failure"));
            }]))
        });
        srv.listen(port);
        return srv;
    }
    const SERVER_FACTORIES = {
        80: mkPlainWebServer,
        25: mkMailRouter
    }
    logger.info("Service ports:", ports);
    ports.forEach(p => {
        const serverFactory = SERVER_FACTORIES[p];
        if (serverFactory) handlers[p] = serverFactory;
        else handlers[p] = mkTlsServer;
    });
    const pending = [];
    ports.forEach(p => {
        servers[p] = handlers[p](p);
        pending.push(new Promise((resolve, reject) =>
            servers[p]
                .on('listening',
                    () => resolve()
                )
                .on('error', (e) => {
                    logger.error("Connection error:", e);
                })
        ))

    });
    return all(pending);

}
async function shutdown() {
    const pending = [];
    Object.entries(servers).forEach(([port, server]) =>
        pending.push(new Promise((resolve, reject) => server.close(err => {
            if (err) reject(err);
            else resolve();
        })))
    );
    return all(pending);
}

module.exports = {
    main, shutdown
}