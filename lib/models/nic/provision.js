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
var common = require('./common');
var constants = require('../../util/constants');
var errors = require('../../util/errors');
var mod_ip = require('../ip');
var mod_net = require('../network');
var mod_portolan_moray = require('portolan-moray');
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
 * Provision specific IPs on the specified IPv4 (network_uuid) and
 * IPv6 (network6_uuid) networks.
 */
function ipsOnNetwork(opts, callback) {
    assert.object(opts.baseParams, 'opts.baseParams');

    var params = opts.validated;

    if (opts.ips && opts.err && opts.err.context) {
        var bucket = opts.err.context.bucket;
        var net4_uuid = params.network_uuid;
        var net6_uuid = params.network6_uuid;
        var used_uuid;
        if (net4_uuid && bucket === mod_ip.bucketName(net4_uuid)) {
            used_uuid = net4_uuid;
        }
        if (net6_uuid && bucket === mod_ip.bucketName(net6_uuid)) {
            used_uuid = net6_uuid;
        }
        if (used_uuid !== undefined) {
            var usedErr = new errors.InvalidParamsError(
                constants.msg.INVALID_PARAMS,
                [ errors.duplicateParam('ip', util.format(
                    constants.fmt.IP_EXISTS, used_uuid)) ]);
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


/**
 * Provision an IP on a network pool
 *
 * This function should be called bound to an object with the fields:
 *
 * - network_pool: The network pool object on which we're provisioning
 * - net_attr: The name of the attribute to check for already selected networks
 * - uuid_attr: The name of the attribute to check for the selected network
 */
function ipOnNetworkPool(opts, callback) {
    assert.object(this.pool, 'pool');
    assert.string(this.net_attr, 'net_attr');
    assert.string(this.uuid_attr, 'uuid_attr');

    var params = opts.validated;
    var network_pool = this.pool;
    var network = params[this.net_attr];
    var uuid_attr = this.uuid_attr;

    if (!opts.poolUUIDs) {
        opts.poolUUIDs = clone(network_pool.networks);
        opts.log.debug({ poolUUIDs: opts.poolUUIDs },
            'ipOnNetworkPool: network list');
    }

    var haveNetErr = (opts.err && opts.err.context ===
        mod_ip.bucketName(params[uuid_attr]));

    // We've been through this function before, but the problem wasn't us -
    // just allow nextIPonNetwork() to handle things
    if (network && !haveNetErr) {
        return addNextIP(network, opts, callback);
    }

    if (!network || haveNetErr) {
        var nextUUID = opts.poolUUIDs.shift();
        if (!nextUUID) {
            var fullErr = new errors.InvalidParamsError('Invalid parameters',
                [ errors.invalidParam(uuid_attr,
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

            // Add the correct network params to the provisioning params
            // object:
            common.saveNetwork(opts.validated, res, true);
            opts.baseParams = mod_ip.params(opts.validated);

            if (opts.ipProvisions && opts.ipProvisions[res.uuid]) {
                opts.ipProvisions[res.uuid].reset();
            }

            return addNextIP(res, opts, callback);
        });
    }

    return addNextIP(opts, callback);
}


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
        opts.nic.network4 = opts.validated.network4;
        opts.nic.network6 = opts.validated.network6;
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
            opts.nic.network4 = opts.validated.network4;
            opts.nic.network6 = opts.validated.network6;
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
        opts.nic.network4 = opts.validated.network4;
        opts.nic.network6 = opts.validated.network6;
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
    var networks = [];
    var network4 = opts.validated.network4;
    var network6 = opts.validated.network6;

    if (network4 && network4.fabric) {
        networks.push(network4);
    }

    if (network6 && network6.fabric) {
        networks.push(network6);
    }

    // we don't always have a network upon creation
    if (networks.length === 0) {
        return callback(null);
    }

    vasync.forEachParallel({
        'inputs': networks,
        'func': function (network, cb) {
            var listOpts = {
                moray: opts.app.moray,
                log: opts.log,
                vnet_id: network.vnet_id
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
    assert.ok(opts.nicFn, 'opts.nicFn');

    var funcs = [ ];
    var params = opts.validated;

    // XXX: When using network pools, we need to select networks such that
    // vlan ids and nic tags match

    if (params.network4_pool) {
        funcs.push(ipOnNetworkPool.bind({
            pool: params.network4_pool,
            net_attr: 'network4',
            uuid_attr: 'network_uuid'
        }));
    }

    if (params.network6_pool) {
        funcs.push(ipOnNetworkPool.bind({
            pool: params.network6_pool,
            net_attr: 'network6',
            uuid_attr: 'network6_uuid'
        }));
    }

    if (params.ips || params.ip) {
        // Want specific IPs
        funcs.push(ipsOnNetwork);
    } else {
        // Just provision the next IP on the specified networks
        if (params.network4) {
            funcs.push(mod_ip.nextIPonNetwork.bind(null, params.network4));
        }
        if (params.network6) {
            funcs.push(mod_ip.nextIPonNetwork.bind(null, params.network6));
        }
    }

    opts.log.debug({
        nicProvFn: opts.nicFn.name,
        // We could only be provisioning a nic:
        ipProvFn: funcs.length === 0 ? 'none' : funcs[0].name,
        baseParams: opts.baseParams,
        validated: opts.validated,
        vnetCns: opts.vnetCns || 'none'
    }, 'provisioning nicAndIP');

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
    nicAndIP: nicAndIP
};
