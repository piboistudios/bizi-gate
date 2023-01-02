const async = require('async');
const net = require('net');
const { Readable } = require('stream');
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
    const DnsRecordset = require('./models/dns.recordset');
    const File = require('./models/file');
    const AcmeChallenge = require('./models/acme.challenge');
    const acme = require('acme-client');
    /**@type {import('axios').AxiosStatic} */
    const axiosStat = require('axios');
    const axios = axiosStat.create({
        validateStatus: () => true,
        headers: {
            "X-Api-Key": "gabedev-tech.QeenbamVk4McTG",
            "Content-Type": "application/vnd.api+json"
        }
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
                backoffMin: 60 * 1000
            });
            const { DNS_MODE } = process.env;
            // if (!DNS_MODE) throw "not_implemented: http-01 challenge";
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
                            throw "no_zone_id";
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
                            throw "no_zone_id";
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

            latest = {};
            latest.csr = '' + csr;
            latest.key = '' + key;
            latest.cert = '' + cert;
            /* Done */

            return latest;
        } catch (e) {
            log.error("Unable to complete acme challenge:", e);
            throw e;
        }
    }

    const { JSONRPCServer, createJSONRPCErrorResponse } = require('json-rpc-2.0')
    const rpc = new JSONRPCServer();
    rpc.addMethod("vhost.registration.complete", async ({
        vhost: vhostId
    }) => {
        const log = logger.sub("vhost.registration.complete");

        /**@type {import('./types').VHost} */
        const vhost = await VirtualHost.findById(vhostId);
        log.debug("V-Host Record:", vhost);
        if (!vhost) {
            throw "Non-existent virtual host assigned to port registration.";
        }
        const stub = vhost.stub;
        log.debug("Populating zone data...");
        await vhost.populate('zone');
        /**@type {import('./types').DnsZone} */
        const dnsZone = vhost.zone;
        log.debug("DNS Zone Record:", dnsZone);
        if (!dnsZone) {
            throw "Non-existent DNS Zone assigned to virtual host for port registration.";
        }


        const zone = dnsZone.dnsName;
        const hostname = [stub, zone].filter(Boolean).join('.');
        await Promise.all(process.env.THIS_HOST.split(',').map(async thisHost => {

            var address_type = net.isIP(thisHost);
            const resourceType = RESOURCE_TYPES[address_type];
            if (resourceType === 'CNAME') return;
            const existingRecordset = await DnsRecordset.findOne({
                stub,
                zone: dnsZone.id,
                resourceType,
                ttl: 300,
                "records.value": thisHost
            });
            if (!existingRecordset) {

                const recordset = new DnsRecordset({
                    stub,
                    zone: dnsZone.id,
                    resourceType,
                    ttl: 300,
                    records: [
                        {
                            value: thisHost
                        }
                    ],
                    routingPolicy: 0
                });
                log.debug("Saving new DNS recordset...", { thisHost, ...recordset.toJSON() });
                await recordset.save();
                log.info("DNS Recordset saved for", hostname, "to point to", `${thisHost}:${process.env.THIS_PORT}`);

            } else {
                log.debug("Using existing recordset...", { thisHost });
            }
        }))
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
        vhost.cert = certFile;
        vhost.key = keyFile;
        await vhost.save();
    })
    const express = require('express');
    const bodyParser = require('body-parser');
    const router = express();
    router.use(bodyParser.json());
    router.get("/", (req, res) => res.status(200).json("OK"))
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
        rpc.receive(jsonRPCRequest).then((jsonRPCResponse) => {
            if (jsonRPCResponse) {
                res.json(jsonRPCResponse);
            } else {
                // If response is absent, it was a JSON-RPC notification method.
                // Respond with no content status (204).
                res.sendStatus(204);
            }
        });

    });

    return router;
}
module.exports = main();