const async = require('async');
const net = require('net');
const { Readable } = require('stream');
const Endpoint = require('./models/gate.endpoint');
const Registration = require('./models/gate.registration');
const RESOURCE_TYPES = {
    0: "CNAME",
    4: "A",
    6: "AAAA"
}
async function main() {
    const { mkLogger } = require('./logger');
    const logger = mkLogger('bizi-acme');
    const log = logger.debug;
    const logError = logger.error;
    const Client = require('./models/client');
    const VirtualHost = require('./models/gate.virtual-host');
    const DnsZone = require('./models/dns.zone');
    const DnsRecordset = require('./models/dns.recordset');
    const File = require('./models/file');
    const AcmeChallenge = require('./models/acme.challenge');
    const acme = require('acme-client');
    /**@type {import('axios').AxiosStatic} */
    const axiosStat = require('axios');
    const qs = require('qs');
    const axios = axiosStat.create({
        validateStatus: () => true,
        headers: {
            "X-Api-Key": "gabedev-tech.QeenbamVk4McTG",
            "Content-Type": "application/vnd.api+json"
        },
        paramsSerializer: (params) => qs.stringify(params, { encode: false }),
    })
    function mkErr(msg, res) {
        logger.error("made error for res:", {
            status: res.status,
            config: res.config,
            headers: res.headers,
            data: res.data
        })
        return new axiosStat.AxiosError(msg, res.status, res.config)
    }
    function parseName(domain) {
        const nameParts = domain.split('.');
        const tld = nameParts.pop();
        const host = nameParts.pop();
        const stub = nameParts.length ? nameParts.join('.') : undefined;
        const zone = [host, tld].filter(Boolean).join('.');
        return { stub, zone };
    }
    async function runAcmeChallenge(domain) {
        const log = logger.sub('runAcmeChallenge');
        try {


            log.info("begin...");
            const client = new acme.Client({
                directoryUrl: acme.directory[process.env.ACME_DIRECTORY || 'letsencrypt'][process.env.ACME_ENVIRONMENT || 'staging'],
                accountKey: await acme.crypto.createPrivateKey(),
                backoffAttempts: 32,
                backoffMax: 60 * 1000 * 120 + 1,
                backoffMin: 10 * 1000
            });
            const { DNS_MODE } = process.env;
            // if (!DNS_MODE) throw new Error("not_implemented: http-01 challenge");
            /* Create CSR */
            const [key, csr] = await acme.crypto.createCsr({
                commonName: domain
            });
            /* Certificate */
            const cert = await client.auto({
                csr,
                email: 'hostmaster@gabedev.tech',
                termsOfServiceAgreed: true,
                skipChallengeVerification: true,
                challengePriority: DNS_MODE ? ['dns-01', 'http-01'] : ['http-01', 'dns-01'],
                challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                    if (challenge.type === 'http-01') {

                        log.debug("challengeCreateFn()...", { authz, challenge, keyAuthorization });
                        const route = "/acme-challenge/" + challenge.token;
                        log.debug("Creating route", { route });
                        const acmeChallenge = new AcmeChallenge({
                            token: challenge.token,
                            keyAuthorization
                        });
                        await acmeChallenge.save();

                    } else {
                        const { stub, zone } = parseName(authz.identifier.value);
                        const zoneRes = await axios.get(`https://graph.bizi.ly/dns.zones?filter=(dnsName,:eq,\`${zone}\`)`);
                        if (zoneRes.status !== 200) {
                            const err = mkErr("Unable to retrieve zone", zoneRes);
                            logger.fatal(err);
                            throw err;
                        }

                        const zoneId = zoneRes.data?.data?.[0]?.id;
                        if (!zoneId) {
                            logger.fatal("Unable to retrieve zone id:", zoneRes.data);
                            throw new Error("no_zone_id")
                        }
                        const dnsRecord = ['_acme-challenge', stub].filter(Boolean).join('.');
                        const recordValue = keyAuthorization;

                        log.debug(`Creating TXT record for ${authz.identifier.value}: ${dnsRecord}`);

                        /* Replace this */
                        log.debug(`Would create TXT record "${dnsRecord}" with value "${recordValue}"`);
                        // await dnsProvider.createRecord(dnsRecord, 'TXT', recordValue);
                        const recordsetCreateRes = await axios.post("https://graph.bizi.ly/dns.recordsets", {
                            "data": [
                                {
                                    "type": "dns.recordsets",
                                    "attributes": {
                                        "stub": dnsRecord,
                                        "resourceType": "TXT",
                                        "ttl": 1,
                                        "records": [
                                            {
                                                "value": recordValue
                                            }
                                        ],
                                        "routingPolicy": 0

                                    },
                                    "relationships": {
                                        "zone": {
                                            "data": {
                                                "id": zoneId,
                                                "type": "dns.zones"
                                            }
                                        }
                                    }
                                },
                                {
                                    "type": "dns.recordsets",
                                    "attributes": {
                                        "stub": dnsRecord,
                                        "resourceType": "NS",
                                        "ttl": 1,
                                        "records": [
                                            {
                                                "value": "ns-a1.bizi.ly"
                                            },
                                            {
                                                "value": "ns-a2.bizi.ly"
                                            }
                                        ],
                                        "routingPolicy": 0

                                    },
                                    "relationships": {
                                        "zone": {
                                            "data": {
                                                "id": zoneId,
                                                "type": "dns.zones"
                                            }
                                        }
                                    }
                                }
                            ]

                        });
                        if (recordsetCreateRes.status !== 201) {
                            const err = mkErr("Unable to create DNS Recordset:", recordsetCreateRes);
                            logger.fatal(err);
                            throw err;
                        }
                        await new Promise((resolve, reject) => setTimeout(() => resolve(), 1000 * 60 * 1));
                    }

                },
                challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
                    log.debug("challengeRemoveFn()...", { authz, challenge, keyAuthorization });
                    if (challenge.type === 'http-01') {
                        const route = "/acme-challenge/" + challenge.token;
                        log.debug("Removing route", route, " for ", challenge.token);
                        log.debug("Key Authorization: ", keyAuthorization);
                        const { token } = challenge;
                        await AcmeChallenge.deleteOne({
                            token,
                            keyAuthorization
                        });
                    }
                    else {
                        const { stub, zone } = parseName(authz.identifier.value);

                        const zoneRes = await axios.get(`https://graph.bizi.ly/dns.zones?filter=(dnsName,:eq,\`${zone}\`)`);

                        if (zoneRes.status !== 200) {
                            const err = mkErr("Unable to retrieve zone", zoneRes);
                            logger.fatal(err);
                            throw err;
                        }

                        const zoneId = zoneRes.data?.data?.[0]?.id;
                        if (!zoneId) {
                            logger.fatal("Unable to retrieve zone id:", zoneRes.data);
                            throw new Error("no_zone_id")
                        }
                        const dnsRecord = ['_acme-challenge', stub].filter(Boolean).join('.');

                        const recordValue = keyAuthorization;

                        const recordsetRes = await axios.get(`https://graph.bizi.ly/dns.recordsets?filter=(:and,(zone,:eq,\`${zoneId}\`),(stub,:eq,\`${dnsRecord}\`))`);
                        if (!recordsetRes.status === 200) {
                            const err = mkErr("Unable to retrieve recordset", recordsetRes);
                            logger.fatal(err);
                            throw err;
                        }

                        const recordsetIds = recordsetRes.data?.data?.map(d => d.id);
                        log.debug(`Removing TXT record for ${authz.identifier.value}: ${dnsRecord}`);

                        /* Replace this */
                        log.debug(`Would remove TXT record "${dnsRecord}" with value "${recordValue}"`);
                        const recordsetDeleteRes = await Promise.all(recordsetIds.map(recordsetId => axios.delete("https://graph.bizi.ly/dns.recordsets/" + recordsetId)));
                        if (recordsetDeleteRes.every(r => r.status !== 204)) {
                            const err = mkErr("Unable to delete DNS Recordset:", recordsetDeleteRes);
                            logger.fatal(err);
                            throw err;
                        }
                        logger.info("Successfully removed record");
                        // await dnsProvider.removeRecord(dnsRecord, 'TXT');
                    }
                }
            });

            let result = {};
            result.csr = '' + csr;
            result.key = '' + key;
            result.cert = '' + cert;
            /* Done */

            return result;
        } catch (e) {
            log.error("Unable to complete acme challenge:", e);
            throw e;
        }
    }

    const { JSONRPCServer, createJSONRPCErrorResponse } = require('json-rpc-2.0')
    const rpc = new JSONRPCServer();
    async function getDnsName(vhost) {
        const log = logger.sub("getDnsName");

        const stub = vhost.stub;
        log.debug("Populating zone data...");
        await vhost.populate('zone');
        /**@type {import('./types').DnsZone} */
        const dnsZone = vhost.zone;
        log.debug("DNS Zone Record:", dnsZone);
        if (!dnsZone) {
            throw new Error("Non-existent DNS Zone assigned to virtual host for port registration.");
        }
        return [stub, dnsZone.dnsName].filter(Boolean).join('.');
    }
    rpc.addMethod('gate.registration.complete', async ({
        gateRegistration: gateRegistrationId
    }) => {
        const log = logger.sub("gate.registration.complete");

        const gateRegistration = await Registration.findById(gateRegistrationId);
        if (!gateRegistration) {
            throw new Error("Non-existent gate registration");
        }
        await gateRegistration.populate('src.host');
        const vhost = gateRegistration.src.host;
        const endpoint = await Endpoint.findOne({
            ports: gateRegistration.src.port
        });
        if (!endpoint) {
            throw new Error("No endpoint hosting port. Try another port.")
        }
        const hostname = await getDnsName(vhost);
        const dnsZone = vhost.zone;
        const stub = vhost.stub;
        const ip = endpoint.host;
        var address_type = net.isIP(ip);
        const resourceType = RESOURCE_TYPES[address_type];
        // if (resourceType === 'CNAME') {
        //     log.fatal("Invalid endpoint host:", ip);
        //     throw new Error("Endpoint misconfigured; please contact hostmaster@bizi.ly")
        // }
        const existingRecordset = await DnsRecordset.findOne({
            stub,
            zone: dnsZone.id,
            resourceType,
        });
        if (!existingRecordset) {

            const recordset = new DnsRecordset({
                stub,
                zone: dnsZone.id,
                resourceType,
                ttl: 300,
                records: [
                    {
                        value: ip
                    }
                ],
                routingPolicy: 0
            });
            log.debug("Saving new DNS recordset...", { ip, ...recordset.toJSON() });
            await recordset.save();
            log.info("DNS Recordset saved for", hostname, "to point to", `${ip}`);

        } else {
            log.debug("Using existing recordset...", { ip });
        }
    });
    rpc.addMethod("vhost.registration.complete", async ({
        vhost: vhostId
    }) => {
        const log = logger.sub("vhost.registration.complete");

        /**@type {import('./types').VHost} */
        const vhost = await VirtualHost.findById(vhostId);
        log.debug("V-Host Record:", vhost);
        if (!vhost) {
            throw new Error("Non-existent virtual host assigned to port registration.");
        }


        const hostname = await getDnsName(vhost);

        /**@todo start an acme rotation for registration; retrying with back-off indefinitely, max back-off 30 mins */
        const pems = await async.retry({
            times: 8,
            interval: count => count * 1000 * 60
        }, async.asyncify(() => runAcmeChallenge(hostname)));
        log.debug("Got ACME PEMS:", pems);
        const keyFile = await File.write({
            filename: hostname + ".key.pem"
        }, Readable.from(pems.key));
        const certFile = await File.write({
            filename: hostname + '.cert.pem'
        }, Readable.from(pems.cert));
        vhost.cert = certFile.id;
        vhost.key = keyFile.id;
        await vhost.save();
    });
    rpc.addMethod("dns.zone.bootstrap", async ({
        name,
        domain: dnsName,
        client
    }) => {
        const log = logger.sub("dns.zone.bootstrap");
        log.info("Start");
        log.info("Checking for existing zone...");
        const existingZone = await DnsZone.findOne({
            $or: [
                {
                    name,
                    client
                },
                {
                    dnsName
                }
            ]
        });
        log.info("Zone exists?", existingZone);
        if (existingZone) throw new Error("Zone already exists.");
        log.info("Creating dns zone:", { name, dnsName, client });
        const zone = new DnsZone({
            name,
            dnsName,
            client
        });
        await zone.save();
        log.info("Zone created");
        log.debug(zone);
        const nsRecordset = new DnsRecordset({
            zone: zone.id,
            ttl: 300,
            routingPolicy: 0,
            resourceType: "NS",
            records: [
                ['ns-a1.bizi.ly', 'ns-a2.bizi.ly'].map(r => ({
                    value: r,
                    weight: 0
                }))
            ]
        });
        const soaRecordset = new DnsRecordset({
            zone: zone.id,
            ttl: 300,
            routingPolicy: 0,
            resourceType: "SOA",
            records: [
                ['ns-a1.bizi.ly hostmaster.bizi.ly 2 21600 3600 259200 300'].map(r => ({
                    value: r,
                    weight: 0
                }))
            ]
        });
        log.info("Creating NS and SOA recordsets");
        await Promise.all([nsRecordset, soaRecordset].map(d => d.save()));
        log.info("Recordsets created");
        log.debug(
            nsRecordset,
            soaRecordset
        );
        const ids = {
            ids: {
                zone: zone.id,
                ns: nsRecordset.id,
                soa: soaRecordset.id
            }
        };
        log.info("Returning ids");
        log.debug(ids);
        return ids;
    });
    const express = require('express');
    const bodyParser = require('body-parser');
    const router = express();
    const nameparser = require('tldts');
    const fs = require('fs');
    const parseDomain = require('parse-domains');
    const mtaStsTemplate = fs.readFileSync('mta-sts-template.txt');
    const mkMtaSts = require('handlebars').compile('' + mtaStsTemplate);
    router.use(bodyParser.json());
    router.get("/", (req, res) => res.status(200).json("OK"))
    router.get("/.well-known/mta-sts.txt", async (req, res, next) => {
        const log = logger.sub('.well-known-mta-sts');
        const parsed = await parseDomain(req.hostname);
        const subParts = parsed.subdomain.split('.');
        if (subParts.indexOf('mta-sts') === -1) {
            log.error("Invalid hostname:", parsed);
            return res.status(404).json("NOT FOUND");
        }
        const subdomain = subParts.filter(p => p !== 'mta-sts').join('.');
        const zone = await DnsZone.findOne({
            dnsName: parsed.domain
        });
        const dnsZones = await DnsZone.find({
            dnsName: new RegExp(`((${parsed.subdomain}\.)|^)` + parsed.domain + '$', 'i')
        });
        if (!zone) {
            log.error("DNS Zone does not exist:", parsed);
            return res.status(404).json("NOT FOUND");
        }
        const mxRecords = await DnsRecordset.find({
            $or: dnsZones.map(z => {
                return {
                    zone: z.id,
                    resourceType: 'MX'
                }
            })
        });

        if (!mxRecords.length) {
            log.error("MX Records not found:", parsed, zone);
            return res.status(404).json("NOT FOUND");
        }
        res.type('txt');
        res.status(200).send(mkMtaSts({
            mxs: mxRecords.flatMap(r => r.records.map(r => r.value))
        }));
    });
    router.get("/.well-known/acme-challenge/:token", async (req, res) => {
        const { token } = req.params;
        const acmeChallenge = await AcmeChallenge.findOne({
            token
        });
        if (!acmeChallenge) {
            return res.status(404).end("NOT FOUND");
        }
        res.status(200).send(acmeChallenge.keyAuthorization)
    });
    rpc.guard = async (req, res, next) => {
        const apiKey = req.headers['x-api-key'];
        const unauthzd = createJSONRPCErrorResponse(req?.body?.id, 401, "unauthorized");
        if (!apiKey) {
            logger.error("Request missing API Key (request headers):", req.headers);
            return res.status(401).json(unauthzd);

        }
        const [key, secret] = apiKey.split('.');
        const client = await Client.findOne({
            key
        });
        if (!client) {
            logger.error("No client found (request headers):", req.headers);
            return res.status(401).json(unauthzd);
        }
        if (!await client.verifySecret(secret)) {
            logger.error("Invalid client secret (request headers):", req.headers);
            return res.status(401).json(unauthzd);
        }
        req.client = client;
        next();
    };
    // rpc.guard = guard;
    router.post("/rpc", rpc.guard, async (req, res, next) => {
        const jsonRPCRequest = req.body;
        // server.receive takes a JSON-RPC request and returns a promise of a JSON-RPC response.
        // It can also receive an array of requests, in which case it may return an array of responses.
        // Alternatively, you can use server.receiveJSON, which takes JSON string as is (in this case req.body).
        rpc.receive(jsonRPCRequest).then((jsonRPCResponse, ...rest) => {
            if (jsonRPCResponse) {
                res.json(jsonRPCResponse);
            } else {
                logger.debug("Rest of args?", { rest });
                // If response is absent, it was a JSON-RPC notification method.
                // Respond with no content status (204).
                res.sendStatus(204);
            }
        });

    });

    return router;
}
module.exports = main();