/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2016, Joyent, Inc.
 */

/*
 * nic model: provisioning functions for nics and IPs
 */

'use strict';

var assert = require('assert-plus');
var clone = require('clone');
var constants = require('../../util/constants');
var errors = require('../../util/errors');
var jsprim = require('jsprim');
var mod_ip = require('../ip');
var mod_net = require('../network');
var Nic = require('./obj').Nic;
var restify = require('restify');
var util = require('util');
var util_common = require('../../util/common');
var util_mac = require('../../util/mac');
var vasync = require('vasync');



// --- Internal functions



/**
 * Calls the next IP provisioning function, but prevents stop errors
 * from stopping the provisioning loop.
 */
function addNextIP(network, opts, callback) {
    mod_ip.nextIPonNetwork(network, opts, function (err) {
        if (err && err.stop) {
            delete err.stop;
        }

        return callback(err);
    });
}


/**
 * If we have an existing NIC and it has provisioned IP addresses,
 * check if it contains any addresses that we're no longer using,
 * and free them.
 */
function freeOldIPs(opts, callback) {
    opts._removeIPs.forEach(function (oldIP) {
        opts.batch.push(oldIP.batch({ free: true }));
    });

    callback();
}


/**
 * Provision specific IPs on the specified network
 */
function ipsOnNetwork(opts, callback) {
    assert.object(opts.baseParams, 'opts.baseParams');

    var params = opts.validated;

    if (opts.ips && opts.err && opts.err.context) {
        var key = opts.err.context.key;
        var used_ip;
        var used_uuid;
        var abort = params._ips.some(function (ip) {
            var uuid = ip.params.network.uuid;
            if (key === ip.key()) {
                used_ip = ip.address.toString();
                used_uuid = uuid;
                return true;
            }
            return false;
        });
        if (abort) {
            var usedErr = new errors.InvalidParamsError(
                constants.msg.INVALID_PARAMS,
                [ errors.duplicateParam('ip', util.format(
                    constants.fmt.IP_EXISTS, used_ip, used_uuid)) ]);
            usedErr.stop = true;
            return callback(usedErr);
        }
    }

    var ips = [];

    if (opts.hasOwnProperty('_provisionableIPs')) {
        // The IPs already exist in moray, but aren't taken by someone else
        opts._provisionableIPs.forEach(function (ip) {
            var updated = mod_ip.createUpdated(ip, opts.baseParams);

            ips.push(updated);
            opts.batch.push(updated.batch());
        });
    } else {
        params._ips.forEach(function (ip) {
            var ipParams = clone(opts.baseParams);
            ipParams.ipaddr = ip.address;
            ipParams.network = ip.params.network;
            ipParams.network_uuid = ip.params.network.uuid;

            var updated = new mod_ip.IP(ipParams);

            ips.push(updated);
            opts.batch.push(updated.batch());
        });
    }

    opts.ips = opts.ips.concat(ips);

    return callback();
}


function NetworkProvision(network, count) {
    assert.object(network, 'network');
    assert.finite(count, 'count');
    this.network = network;

    Object.seal(this);
}


NetworkProvision.prototype.provision =
    function ipOnNetwork(opts, callback) {
    mod_ip.nextIPonNetwork(this.network, opts, callback);
};


function NetworkPoolProvision(pool, count, field) {
    assert.object(pool, 'pool');
    assert.finite(count, 'count');
    assert.string(field, 'field');

    this.network = null;
    this.pool = pool;
    this.count = count;
    this.field = field;
    this.poolUUIDs = pool.networks;

    Object.seal(this);
}


/**
 * Provision an IP on a network pool
 */
NetworkPoolProvision.prototype.provision =
    function ipOnNetworkPool(opts, callback) {
    var self = this;

    var haveNetErr = (opts.err && opts.err.context ===
        mod_ip.bucketName(self.network.uuid));

    // We've been through this function before, but the problem wasn't us -
    // just allow nextIPonNetwork() to handle things
    if (self.network && !haveNetErr) {
        return addNextIP(self.network, opts, callback);
    }

    if (!self.network || haveNetErr) {
        var nextUUID = self.poolUUIDs.shift();
        if (!nextUUID) {
            var fullErr = new errors.InvalidParamsError('Invalid parameters',
                [ errors.invalidParam(self.field,
                    constants.POOL_FULL_MSG) ]);
            fullErr.stop = true;
            return callback(fullErr);
        }

        opts.log.debug({ nextUUID: nextUUID }, 'Trying next network in pool');

        var netGetOpts = {
            app: opts.app,
            log: opts.log,
            params: { uuid: nextUUID }
        };

        return mod_net.get(netGetOpts, function (err, res) {
            if (err) {
                opts.log.error(err, 'provisionIPonNetworkPool: error getting ' +
                    'network %s', nextUUID);
                return callback(err);
            }

            self.network = res;

            return addNextIP(res, opts, callback);
        });
    }

    // XXX: Need a test that passes through here
    // Should be:
    // return addNextIP(network, opts, callback);
    return addNextIP(opts, callback);
};


/**
 * Adds an opts.nic with the MAC address from opts.validated, and adds its
 * batch item to opts.batch.  Intended to be passed to nicAndIP() in
 * opts.nicFn.
 */
function macSupplied(opts, callback) {
    // We've already tried provisioning once, and it was the nic that failed:
    // no sense in retrying

    opts.log.debug({}, 'macSupplied: enter');

    if (opts.nic && opts.err && opts.err.context &&
        opts.err.context.bucket === common.BUCKET.name) {

        var usedErr = new errors.InvalidParamsError(
            constants.msg.INVALID_PARAMS, [ errors.duplicateParam('mac') ]);
        usedErr.stop = true;
        return callback(usedErr);
    }

    opts.nic = new Nic(opts.validated);
    if (opts.ips) {
        opts.nic.ips = opts.ips;
    }

    if (opts.nic.isFabric() && opts.vnetCns) {
        opts.nic.vnetCns = opts.vnetCns;
    }

    return callback();
}


/**
 * Adds an opts.nic with a random MAC address, and adds its batch item to
 * opts.batch.  Intended to be passed to nicAndIP() in opts.nicFn.
 */
function randomMAC(opts, callback) {
    var validated = opts.validated;

    if (!opts.hasOwnProperty('macTries')) {
        opts.macTries = 0;
    }

    opts.log.debug({ tries: opts.macTries }, 'randomMAC: entry');

    // If we've already supplied a MAC address and the error isn't for our
    // bucket, we don't need to generate a new MAC - just re-add the existing
    // nic to the batch
    if (validated.mac && (!opts.err || !opts.err.hasOwnProperty('context') ||
        opts.err.context.bucket !== 'napi_nics')) {

        opts.nic = new Nic(validated);
        if (opts.ips) {
            opts.nic.ips = opts.ips;
        }

        return callback();
    }

    if (opts.macTries > constants.MAC_RETRIES) {
        opts.log.error({ start: opts.startMac, num: validated.mac,
            tries: opts.macTries },
            'Could not provision nic after %d tries', opts.macTries);
        var err = new restify.InternalError('no more free MAC addresses');
        err.stop = true;
        return callback(err);
    }

    opts.macTries++;

    if (!opts.maxMac) {
        opts.maxMac = util_mac.maxOUInum(opts.app.config.macOUI);
    }

    if (!validated.mac) {
        validated.mac = util_mac.randomNum(opts.app.config.macOUI);
        opts.startMac = validated.mac;
    } else {
        validated.mac++;
    }

    if (validated.mac > opts.maxMac) {
        // We've gone over the maximum MAC number - start from a different
        // random number
        validated.mac = util_mac.randomNum(opts.app.config.macOUI);
    }

    opts.nic = new Nic(validated);
    if (opts.ips) {
        opts.nic.ips = opts.ips;
    }

    opts.log.debug({}, 'randomMAC: exit');
    return callback();
}



// --- Exported functions



/**
 * Adds parameters to opts for provisioning a nic and an optional IP
 */
function addParams(opts, callback) {
    opts.nicFn = opts.validated.mac ? macSupplied : randomMAC;
    opts.baseParams = mod_ip.params(opts.validated);
    if (opts.validated.hasOwnProperty('_ips')) {
        opts._provisionableIPs = opts.validated._ips;
    }
    return callback();
}

/**
 * Add the batch item for the nic in opts.nic opts.batch, as well as an
 * item for unsetting other primaries owned by the same owner, if required.
 */
function addNicToBatch(opts) {
    opts.log.debug({
        vnetCns: opts.vnetCns,
        ips: opts.nic.ips ?
            opts.nic.ips.map(function (ip) { return ip.v6address; }) : 'none'
    }, 'addNicToBatch: entry');
    opts.batch = opts.batch.concat(opts.nic.batch({
       log: opts.log,
       vnetCns: opts.vnetCns
    }));
}


/**
 * If the network provided is a fabric network, fetch the list of CNs also
 * on that fabric network, for the purpose of SVP log generation.
 */
function listVnetCns(opts, callback) {
    // Collect networks that the NIC's on
    assert.ok(opts.ips, 'ips');
    var networks = {};

    opts.ips.forEach(function (ip) {
        var network = ip.params.network;
        if (network.fabric) {
            networks[network.uuid] = network;
        }
    });

    // we don't always have a network upon creation
    if (networks.length === 0) {
        callback(null);
        return;
    }

    vasync.forEachParallel({
        'inputs': Object.keys(networks),
        'func': function (uuid, cb) {
            var listOpts = {
                moray: opts.app.moray,
                log: opts.log,
                vnet_id: networks[uuid].vnet_id
            };

            common.listVnetCns(listOpts, cb);
        }
    }, function (err, res) {
        if (err) {
            return callback(err);
        }

        opts.vnetCns = res.operations.reduce(function (acc, curr) {
            return acc.concat(curr.result);
        }, []);

        opts.log.debug({vnetCns: opts.vnetCns}, 'provision.listVnetCns exit');

        return callback(null);
    });
}


function nicBatch(opts, cb) {
    opts.log.debug({ vnetCns: opts.vnetCns }, 'nicBatch: entry');
    addNicToBatch(opts);

    opts.log.debug({ batch: opts.batch }, 'nicBatch: exit');
    return cb();
}

/**
 * Provisions a nic and optional IP - contains a critical section that ensures
 * via retries that ips (and, less likely, MACs) are not duplicated.
 *
 * @param opts {Object}:
 * - baseParams {Object}: parameters used for creating the IP (required)
 * - nicFn {Function}: function that populates opts.nic
 */
function nicAndIP(opts, callback) {
    assert.object(opts.baseParams, 'opts.baseParams');
    assert.func(opts.nicFn, 'opts.nicFn');

    var funcs = [ ];
    var params = opts.validated;

    var addNetworks = params.add_networks || {};
    var addPools = params.add_pools || {};

    var network4 = params.network4;
    var network4_pool = params.network4_pool;

    // XXX: When using network pools, we need to select networks such that
    // vlan ids and nic tags match

    if (network4_pool && !addPools.hasOwnProperty(network4_pool.uuid)) {
        addPools[network4_pool.uuid] =
            new NetworkPoolProvision(network4_pool, 1, 'network_uuid');
    }

    if (params._ips) {
        // Want specific IPs
        funcs.push(ipsOnNetwork);
    } else if (network4 && !addNetworks.hasOwnProperty(network4.uuid)) {
        addNetworks[network4.uuid] =
            new NetworkProvision(network4, 1);
    }

    function pushProvisioner(_, provisioner) {
        funcs.push(provisioner.provision.bind(provisioner));
    }

    jsprim.forEachKey(addNetworks, pushProvisioner);
    jsprim.forEachKey(addPools, pushProvisioner);

    opts.log.debug({
        nicProvFn: opts.nicFn.name,
        // We could only be provisioning a nic:
        ipProvFns: funcs.map(function (fn) { return fn.name; }),
        baseParams: opts.baseParams,
        validated: opts.validated,
        vnetCns: opts.vnetCns || 'none'
    }, 'provisioning nicAndIP');

    // If we have any old IP addresses, we'll remove them
    if (opts._removeIPs && opts._removeIPs.length > 0) {
        funcs.push(freeOldIPs);
    }

    // locates the vnetCns in the create and update/provision code paths.
    funcs.push(listVnetCns);

    // This function needs to go after the IP provisioning functions in the
    // chain, as the nic needs a pointer to what IP address it has
    funcs.push(opts.nicFn);

    funcs.push(nicBatch);

    funcs.push(common.commitBatch);

    util_common.repeat(function (cb) {
        // Reset opts.batch - it is the responsibility for functions in the
        // pipeline to re-add their batch data each time through the loop
        opts.batch = [];
        opts.ips = [];

        vasync.pipeline({
            arg: opts,
            funcs: funcs
        }, function (err) {
            if (err) {
                opts.log.warn({ err: err, final: err.stop }, 'error in repeat');
                if (err.stop) {
                    // No more to be done:
                    return cb(err, null, false);
                }

                // Need to retry. Set opts.err so the functions in funcs
                // can determine if they need to change their params
                opts.err = err;
                return cb(null, null, true);
            }
            return cb(null, opts.nic, false);
        });
    }, function (err, res) {
        if (err) {
            return callback(err);
        }

        opts.log.info({ params: params, obj: res.serialize() }, 'Created nic');

        return callback(null, res);
    });
}

module.exports = {
    addParams: addParams,
    addNicToBatch: addNicToBatch,
    NetworkProvision: NetworkProvision,
    NetworkPoolProvision: NetworkPoolProvision,
    nicAndIP: nicAndIP
};


/*
 * Circular dependencies 'require'd here. DON'T ASK QUESTIONS.
 */
var common = require('./common');
