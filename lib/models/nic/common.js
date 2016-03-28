/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2016, Joyent, Inc.
 */

/*
 * nic model: common code
 */

'use strict';

var assert = require('assert-plus');
var constants = require('../../util/constants');
var errors = require('../../util/errors');
var mod_ip = require('../ip');
var mod_net = require('../network');
var mod_pool = require('../network-pool');
var mod_portolan_moray = require('portolan-moray');
var util = require('util');
var util_mac = require('../../util/mac');
var validate = require('../../util/validate');
var vasync = require('vasync');


// --- Globals

var BUCKET = require('./bucket').BUCKET;


// --- Internal helpers

/**
 * Save a network to a NIC. IPv6 networks get saved as network6, and IPv4
 * networks get saved as network4. This is for when information needs to be
 * filled in later. These fields also get filled in during validation using
 * validateNetwork().
 */
function saveNetwork(nic, network, save_uuid) {
    switch (network.subnetType) {
    case 'ipv4':
        nic.network4 = network;
        if (save_uuid) {
            nic.network_uuid = network.uuid;
        }
        break;
    case 'ipv6':
        nic.network6 = network;
        if (save_uuid) {
            nic.network6_uuid = network.uuid;
        }
        break;
    default:
        throw new Error('Unknown subnet type "' + network.subnetType + '"');
    }
}


/**
 * Validates a MAC address
 */
function validateMAC(name, mac, callback) {
    var macNum = util_mac.macAddressToNumber(mac);
    if (!macNum) {
        return callback(errors.invalidParam(name,
            'invalid MAC address'));
    }

    return callback(null, macNum);
}


/**
 * Validates a network UUID and ensures that the network exists
 */
function validateNetworkPool(app, log, resname, name, uuid, callback) {
    mod_pool.get(app, log, { uuid: uuid }, function (err2, res) {
        if (err2) {
            if (err2.name === 'ResourceNotFoundError') {
                return callback(errors.invalidParam(name,
                    'network does not exist'));
            }

            return callback(err2);
        }

        if (name === 'network_uuid' && res.type !== 'ipv4') {
            return callback(errors.invalidParam(name, util.format(
                constants.fmt.NET_BAD_AF, 'IPv4')));
        } else if (name === 'network6_uuid' && res.type !== 'ipv6') {
            return callback(errors.invalidParam(name, util.format(
                constants.fmt.NET_BAD_AF, 'IPv6')));
        }

        var toReturn = {};
        toReturn[resname + '_pool'] = res;
        toReturn[name] = res.uuid;
        return callback(null, null, toReturn);
    });
}


/**
 * Validates a network UUID
 */
function validateNetworkUUID(name, uuid, callback) {
    if (uuid === 'admin') {
        return callback(null, uuid);
    }

    return validate.UUID(name, uuid, callback);
}


/**
 * Validate that the subnet contains the IP address
 */
function validateSubnetContainsIPs(opts, parsedParams, callback) {
    var app = opts.app;
    var log = opts.log;
    var ips = parsedParams.ips;
    var _ips = [];

    vasync.forEachPipeline({
        inputs: ips,
        func: function _validateSubnetContainsIP(ip, cb) {
            var network, network_pool, field;
            var type = ip.kind();

            switch (type) {
            case 'ipv4':
                network = parsedParams.network4;
                network_pool = parsedParams.network4_pool;
                field = 'network_uuid';
                break;
            case 'ipv6':
                network = parsedParams.network6;
                network_pool = parsedParams.network6_pool;
                field = 'network6_uuid';
                break;
            default:
                return cb(errors.invalidParam(opts.ips_field, util.format(
                    constants.fmt.IP_AF_UNRECOGNIZED, type)));
            }

            // Not allowed to provision an IP on a network pool
            if (network_pool !== undefined) {
                return cb(errors.invalidParam(opts.ips_field,
                    constants.POOL_IP_MSG));
            }

            if (network === undefined) {
                return cb(errors.invalidParam(opts.ips_field, util.format(
                    constants.fmt.IP_AF_NETWORK_MISSING, type, field)));
            }

            if (!ip.match(network.subnetStart, network.subnetBits)) {
                return cb(errors.invalidParam(opts.ips_field, util.format(
                    constants.fmt.IP_OUTSIDE, ip.toString(), network.uuid)));
            }

            var getOpts = {
                app: app,
                log: log,
                params: {
                    ip: ip,
                    network: network,
                    network_uuid: network.uuid
                },
                // If it's missing in moray, return an object anyway:
                returnObject: true
            };
            mod_ip.get(getOpts, function (err, res) {
                if (err) {
                    // XXX : return different error here
                    return cb(err);
                }

                // Don't allow taking another nic's IP on create if it's taken
                // by something else (server, zone)
                if (opts.create && !res.provisionable()) {
                    return cb(errors.usedByParam(opts.ips_field,
                        res.params.belongs_to_type,
                        res.params.belongs_to_uuid,
                        util.format(constants.fmt.IP_IN_USE,
                            res.params.belongs_to_type,
                            res.params.belongs_to_uuid)));
                }

                _ips.push(res);
                return cb();
            });
        }
    }, function (err) {
        if (err) {
            callback(err);
            return;
        }

        parsedParams._ips = _ips;
        callback();
    });
}



// --- Exported functions



/**
 * Validates a network UUID and ensures that the network exists
 */
function validateNetwork(app, log, resname, name, uuid, callback) {
    validateNetworkUUID(name, uuid, function (err) {
        if (err) {
            return callback(err);
        }

        mod_net.get({ app: app, log: log, params: { uuid: uuid } },
                function (err2, res) {
            if (err2) {
                if (err2.name === 'ResourceNotFoundError') {
                    return validateNetworkPool(app, log, resname, name, uuid,
                        callback);
                }

                return callback(err2);
            }

            if (name === 'network_uuid' && res.subnetType !== 'ipv4') {
                return callback(errors.invalidParam(name, util.format(
                    constants.fmt.NET_BAD_AF, 'IPv4')));
            } else if (name === 'network6_uuid' && res.subnetType !== 'ipv6') {
                return callback(errors.invalidParam(name, util.format(
                    constants.fmt.NET_BAD_AF, 'IPv6')));
            }

            var toReturn = { };
            toReturn[resname] = res;
            toReturn[name] = res.uuid;
            return callback(null, null, toReturn);
        });
    });
}


/**
 * Validate that the network parameters are valid
 */
function validateNetworkParams(opts, params, parsedParams, callback) {
    var app = opts.app;
    var log = opts.log;
    var ips;

    if (parsedParams.ips) {
        ips = parsedParams.ips;
        opts.ips_field = 'ips';
    } else if (parsedParams.ip) {
        ips = [ parsedParams.ip ];
        delete parsedParams.ip;
        parsedParams.ips = ips;
        opts.ips_field = 'ip';
    }

    // If the networks have owner_uuids, make sure we match one of them (or
    // the UFDS admin UUID). Don't check if check_owner is set to false.
    if (parsedParams.owner_uuid &&
        (!parsedParams.hasOwnProperty('check_owner') ||
        parsedParams.check_owner)) {
        if ((parsedParams.network4 &&
            !parsedParams.network4.isOwner(parsedParams.owner_uuid)) ||
            (parsedParams.network6 &&
            !parsedParams.network6.isOwner(parsedParams.owner_uuid))) {
            return callback(errors.invalidParam('owner_uuid',
                constants.OWNER_MATCH_MSG));
        }
    }

    if (parsedParams.network4 && parsedParams.network6) {
        if (parsedParams.network4.params.vlan_id !==
            parsedParams.network6.params.vlan_id) {
            return callback(errors.invalidParam('network_uuid',
                constants.msg.VLAN_IDS_DIFFER));
        }

        if (parsedParams.network4.params.nic_tag !==
            parsedParams.network6.params.nic_tag) {
            return callback(errors.invalidParam('network_uuid',
                constants.msg.NIC_TAGS_DIFFER));
        }
    }

    // network(6)_uuid and ip addresses were specified, so just validate
    if (ips && (params.network_uuid || params.network6_uuid)) {
        return validateSubnetContainsIPs(opts, parsedParams, callback);
    }

    if (!ips) {
        return callback();
    }

    // ip specified, but not network_uuid: vlan_id and nic_tag are needed to
    // figure out what network the nic is on
    var errs = [];
    ['nic_tag', 'vlan_id'].forEach(function (p) {
        if (!parsedParams.hasOwnProperty('vlan_id')) {
            errs.push(errors.missingParam(p, constants.msg.IP_NO_VLAN_TAG));
        }
    });

    if (errs.length !== 0) {
        return callback(errs);
    }

    var query = {
        vlan_id: parsedParams.vlan_id,
        nic_tag: parsedParams.nic_tag
    };

    return mod_net.list({ app: app, log: log, params: query },
            function (err, res) {
        if (err) {
            return callback(err);
        }

        if (res.length === 0) {
            return callback(['nic_tag', 'vlan_id'].map(function (p) {
                return errors.invalidParam(p,
                'No networks found matching parameters');
            }));
        }

        /*
         * Handle the case where we have multiple subnets on one vlan ID
         * by checking that our address is within one of the found networks.
         *
         * XXX: This doesn't work if we're missing and need both network_uuid
         * and network6_uuid, but a DC using IPv6 networks shouldn't be missing
         * UUIDs on NICs, anyways.
         */

        vasync.forEachPipeline({
            func: function (network, cb) {
                saveNetwork(parsedParams, network);
                validateSubnetContainsIPs(opts, parsedParams, function (e) {
                    if (e) {
                        /*
                         * Only InvalidParameter errors indicate that the IP
                         * didn't match this network: others (such as duped
                         * IP errors), we should bubble upwards.
                         */
                        if (e.code === 'InvalidParameter') {
                            cb(null, {input: network, result: false});
                            return;
                        }
                        cb(e);
                        return;
                    }
                    cb(null, {input: network, result: true});
                });
            },
            inputs: res
        }, function (err2, res2) {
            if (err2) {
                /* If we can, simplify this down to a single error. */
                if (err2.ase_errors && err2.ase_errors.length === 1) {
                    return (callback(err2.ase_errors[0]));
                }
                return (callback(err2));
            }

            var contained = res2.operations.filter(function (op) {
                return (typeof (op.result) === 'object' &&
                    op.result.result === true);
            }).map(function (op) {
                return (op.result.input);
            });
            if (contained.length < 1) {
                return (callback(errors.invalidParam(opts.ips_field,
                    util.format(constants.fmt.IP_NONET, parsedParams.nic_tag,
                    parsedParams.vlan_id, parsedParams.ips.join(',')))));
            }
            if (contained.length > 1) {
                var uuids = contained.map(function (n) { return (n.uuid); });
                return (callback(errors.invalidParam(opts.ips_field,
                    util.format(constants.fmt.IP_MULTI, uuids.join(', '),
                    parsedParams.ips.join(',')))));
            }
            saveNetwork(parsedParams, contained[0], true);
            return (callback(null));
        });
    });
}

// --- Common create/updates/delete pipeline functions

/**
 * Provided with a vnet_id, appends the list of vnet cns to opts.vnetCns.
 */
function listVnetCns(opts, callback) {
    assert.object(opts, 'opts');
    assert.number(opts.vnet_id, 'opts.vnet_id');
    assert.object(opts.moray, 'opts.moray');
    assert.object(opts.log, 'opts.log');

    opts.log.debug({ vnet_id: opts.vnet_id }, 'listVnetCns: enter');

    mod_portolan_moray.vl2LookupCns(opts, function (listErr, cns) {
        if (listErr) {
            opts.log.error({ err: listErr, vnet_id: opts.vnet_id },
                'listVnetCns: error fetching cn list on vnet');
            return callback(listErr);
        }

        var vnetCns = Object.keys(cns.reduce(function (acc, cn) {
            acc[cn.cn_uuid] = true; return acc;
        }, {}));

        opts.log.debug({ vnetCns: vnetCns }, 'listVnetCns: exit');

        return callback(null, vnetCns);
    });
}

/**
 * Commits opts.batch to moray
 */
function commitBatch(opts, callback) {
    assert.object(opts, 'opts');
    assert.object(opts.app.moray, 'opts.app.moray');
    assert.object(opts.log, 'opts.log');
    assert.arrayOfObject(opts.batch, 'opts.batch');

    opts.log.info({ batch: opts.batch }, 'commitBatch: enter');

    opts.app.moray.batch(opts.batch, function (err) {
        if (err) {
            opts.log.error(err, 'commitBatch error');
        }

        return callback(err);
    });
}



module.exports = {
    BUCKET: BUCKET,
    commitBatch: commitBatch,
    listVnetCns: listVnetCns,
    saveNetwork: saveNetwork,
    validateMAC: validateMAC,
    validateNetwork: validateNetwork,
    validateNetworkParams: validateNetworkParams
};
