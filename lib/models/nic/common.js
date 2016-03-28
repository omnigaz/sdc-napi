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
var ipaddr = require('ip6addr');
var mod_ip = require('../ip');
var mod_net = require('../network');
var mod_pool = require('../network-pool');
var mod_portolan_moray = require('portolan-moray');
var util = require('util');
var util_ip = require('../../util/ip');
var util_mac = require('../../util/mac');
var validate = require('../../util/validate');
var vasync = require('vasync');


// --- Globals

var BUCKET = require('./bucket').BUCKET;


// --- Internal helpers


/**
 * If an owner_uuid has been specified, and we haven't been explicitly
 * told to ignore it, then make sure it's okay to provision on this
 * network.
 */
function badOwnerUUID(parsedParams, network) {
    // If the network has any owner_uuids, make sure we match one of
    // them (or the UFDS admin UUID). Don't check if check_owner is
    // set to false.
    var check_owner = !parsedParams.hasOwnProperty('check_owner') ||
        parsedParams.check_owner;
    if (parsedParams.hasOwnProperty('owner_uuid') && check_owner &&
        !network.isOwner(parsedParams.owner_uuid)) {
        return true;
    }

    return false;
}


/**
 * Check all of the provided networks to ensure that they all have the same
 * NIC tags and VLAN IDs, which cannot differ on a given NIC.
 */
function checkNetworks(opts, parsedParams, name, uuids, callback) {
    vasync.forEachPipeline({
        'inputs': uuids,
        'func': function (uuid, cb) {
            opts.network_cache.get(uuid, function (err, network) {
                if (err) {
                    cb(err);
                    return;
                }

                if (badOwnerUUID(parsedParams, network)) {
                    cb(errors.invalidParam('owner_uuid',
                        constants.OWNER_MATCH_MSG));
                    return;
                }

                if (parsedParams.nic_tag === undefined) {
                    parsedParams.nic_tag = network.nic_tag;
                } else if (parsedParams.nic_tag !== network.nic_tag) {
                    cb(errors.invalidParam(name,
                        util.format(constants.fmt.NIC_TAGS_DIFFER,
                        parsedParams.nic_tag, network.nic_tag)));
                    return;
                }

                if (parsedParams.vlan_id === undefined) {
                    parsedParams.vlan_id = network.params.vlan_id;
                } else if (parsedParams.vlan_id !== network.params.vlan_id) {
                    cb(errors.invalidParam(name,
                        util.format(constants.fmt.VLAN_IDS_DIFFER,
                        parsedParams.vlan_id, network.params.vlan_id)));
                    return;
                }

                cb();
            });
        }
    }, callback);
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
function validateNetworkPool(app, log, name, uuid, callback) {
    mod_pool.get(app, log, { uuid: uuid }, function (err2, res) {
        if (err2) {
            if (err2.name === 'ResourceNotFoundError') {
                return callback(errors.invalidParam(name,
                    'network does not exist'));
            }

            return callback(err2);
        }

        if (res.type !== 'ipv4') {
            return callback(errors.invalidParam(name, util.format(
                constants.fmt.NET_BAD_AF, 'IPv4')));
        }

        var toReturn = {
            network4_pool: res
        };
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
function validateSubnetContainsIP(opts, name, network, ip, callback) {
    var app = opts.app;
    var log = opts.log;

    assert.object(app, 'app');
    assert.object(log, 'log');

    if (!network.subnet.contains(ip)) {
        callback(errors.invalidParam(name, util.format(
            constants.fmt.IP_OUTSIDE, ip.toString(), network.uuid)));
        return;
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
            return callback(err);
        }

        // Don't allow taking another nic's IP on create if it's taken by
        // something else (server, zone)
        if (opts.create && !res.provisionable()) {
            return callback(errors.usedByParam(name,
                res.params.belongs_to_type,
                res.params.belongs_to_uuid,
                util.format(constants.fmt.IP_IN_USE,
                    res.params.belongs_to_type,
                    res.params.belongs_to_uuid)));
        }

        return callback(null, res);
    });
}

/**
 * Validate that the subnet contains the IP addresses
 */
function validateSubnetContainsIPs(opts, name, network, ips, callback) {
    var _ips = [];

    vasync.forEachPipeline({
        inputs: ips,
        func: function _validateSubnetContainsIP(ip, cb) {
            validateSubnetContainsIP(opts, name, network, ip,
                function (err, res) {
                if (res) {
                    _ips.push(res);
                }
                cb(err);
            });
        }
    }, function (err) {
        callback(err, _ips);
    });
}



// --- Exported functions


function validateMappings(opts, name, mappings, callback) {
    if (typeof (mappings) !== 'object') {
        callback(errors.invalidParam(name, constants.msg.OBJ));
        return;
    }

    var cidrs = Object.keys(mappings);
    var network_uuids = {};

    vasync.forEachPipeline({
        'inputs': cidrs,
        'func': function (cidr, cb) {
            try {
                ipaddr.createCIDR(cidr);
            } catch (e) {
                cb(errors.invalidParam(name, util.format(
                    constants.fmt.CIDR_INVALID, cidr)));
                return;
            }

            var ip = ipaddr.parse(cidr.split('/')[0]);

            function save(err, res) {
                network_uuids[cidr] = res;
                cb(err);
            }

            opts.network_cache.get(mappings[cidr], function (err, network) {
                if (err) {
                    if (err.name === 'ResourceNotFoundError') {
                        cb(errors.invalidParam(name, util.format(
                            'network does not exist')));
                    } else {
                        cb(err);
                    }
                    return;
                }

                validateSubnetContainsIP(opts, name, network, ip, save);
            });
        }
    }, function (err) {
        callback(err, network_uuids);
    });
}


function validateNetworkKeys(opts, name, obj, step, done) {
    if (typeof (obj) !== 'object') {
        done(errors.invalidParam(name, constants.msg.OBJ));
        return;
    }

    var uuids = Object.keys(obj);

    vasync.forEachPipeline({
        'inputs': uuids,
        'func': function (uuid, cb) {
            opts.network_cache.get(uuid, function (err, res) {
                step(err, res, cb);
            });
        }
    }, done);

}


function validateAddIPs(opts, name, add_ips, callback) {
    var add_ipaddrs = {};

    function step(err, network, cb) {
        if (err) {
            if (err.name === 'ResourceNotFoundError') {
                cb(errors.invalidParam(name, 'network does not exist'));
            } else {
                cb(err);
            }
            return;
        }

        var uuid = network.uuid;

        if (!util.isArray(add_ips[uuid])) {
            cb(errors.invalidParam(name, uuid +
                ' should map to an array of addresses to allocate'));
            return;
        }

        add_ipaddrs[uuid] = [];

        vasync.forEachPipeline({
            'inputs': add_ips[uuid],
            'func': function (ip, cb2) {
                try {
                    ip = ipaddr.parse(ip);
                } catch (e) {
                    cb2(errors.invalidParam(name, util.format(
                        constants.fmt.IP_INVALID, ip)));
                    return;
                }

                function save(err2, res) {
                    if (res) {
                        add_ipaddrs[uuid] = res;
                    }
                    cb2(err2);
                }

                validateSubnetContainsIP(opts, name, network, ip, save);
            }
        }, cb);
    }

    validateNetworkKeys(opts, name, add_ips, step, function (err) {
        callback(err, add_ipaddrs);
    });
}


function validateAddNetworks(opts, name, add_nets, callback) {
    var toReturn = {
        add_networks: {},
        add_pools: {}
    };

    function step(err, res, cb) {
        if (err) {
            // XXX: Search for network pools here, too
            // XXX: turn into invalidparam error if missing
            cb(err);
            return;
        }

        var uuid = res.uuid;

        if (typeof (add_nets[uuid]) !== 'number') {
            cb(errors.invalidParam(name, uuid +
                ' should map to the number of addresses to allocate'));
            return;
        }

        toReturn.add_networks[uuid] =
            new provision.NetworkProvision(res, add_nets[uuid]);
        cb();
    }

    validateNetworkKeys(opts, name, add_nets, step, function (err) {
        callback(err, null, toReturn);
    });
}


/**
 * Validates a network UUID and ensures that the network exists
 */
function validateNetwork(opts, name, uuid, callback) {
    var app = opts.app;
    var log = opts.log;
    validateNetworkUUID(name, uuid, function (err) {
        if (err) {
            return callback(err);
        }

        mod_net.get({ app: app, log: log, params: { uuid: uuid } },
                function (err2, res) {
            if (err2) {
                if (err2.name === 'ResourceNotFoundError') {
                    return validateNetworkPool(app, log, name, uuid, callback);
                }

                return callback(err2);
            }

            if (res.subnetType !== 'ipv4') {
                return callback(errors.invalidParam(name, util.format(
                    constants.fmt.NET_BAD_AF, 'IPv4')));
            }

            var toReturn = {
                network4: res
            };
            toReturn[name] = res.uuid;
            return callback(null, null, toReturn);
        });
    });
}


/**
 * Validate that the network parameters are valid
 */
function validateNetworkParams(opts, params, parsedParams, callback) {
    [ 'add_ips', 'add_networks' ].forEach(function (p) {
        if (!parsedParams.hasOwnProperty(p)) {
            parsedParams[p] = {};
        }
    });

    var ipsField;

    var network_uuids = parsedParams.network_uuids || {};
    var provisionIPs = parsedParams.add_ips;
    var allocateIPs = parsedParams.add_networks;
    var unknownIPs = [];

    function planIP(ip) {
        var network_uuid = ip.params.network.uuid;
        if (!provisionIPs.hasOwnProperty(network_uuid)) {
            provisionIPs[network_uuid] = [];
        }
        provisionIPs[network_uuid].push(ip);
    }

    vasync.pipeline({
        'funcs': [
            function _protectExistingIPs(_, cb) {
                // If we have existing addresses and an owner_uuid has been
                // specified, make sure we aren't giving ownership to someone
                // who shouldn't be on the network.
                if (parsedParams.hasOwnProperty('owner_uuid') &&
                    parsedParams._ips) {
                    for (var ip in parsedParams._ips) {
                        if (badOwnerUUID(parsedParams,
                            parsedParams._ips[ip].params.network)) {
                            cb(errors.invalidParam('owner_uuid',
                                constants.OWNER_MATCH_MSG));
                            return;
                        }
                    }
                }
                cb();
            },
            function _planProvision(_, cb) {
                if (parsedParams.hasOwnProperty('ips')) {
                    ipsField = 'ips';
                    parsedParams.ips.forEach(function (ipstr) {
                        if (network_uuids.hasOwnProperty(ipstr)) {
                            planIP(network_uuids[ipstr]);
                        } else {
                            unknownIPs.push(util_ip.toIPAddr(ipstr));
                        }
                    });
                } else if (parsedParams.hasOwnProperty('ip')) {
                    ipsField = 'ip';
                    var ip = parsedParams.ip;
                    parsedParams.ips = [ ip ];
                    delete parsedParams.ip;
                    if (parsedParams.network4) {
                        validateSubnetContainsIP(opts, 'ip',
                            parsedParams.network4, ip,
                            function (err, res) {
                                if (res) {
                                    planIP(res);
                                }
                                cb(err);
                            });
                        return;
                    } else if (parsedParams.network4_pool) {
                        cb(errors.invalidParam('ip', constants.POOL_IP_MSG));
                        return;
                    } else {
                        unknownIPs.push(ip);
                    }
                } else if (parsedParams.network4) {
                    checkNetworks(opts, parsedParams, 'network_uuid',
                        [ parsedParams.network4.uuid ], cb);
                    return;
                }
                cb();
            },
            function _checkNetworkUUIDs(_, cb) {
                var uuids = Object.keys(provisionIPs);
                checkNetworks(opts, parsedParams, 'add_ips', uuids, cb);
            },
            function _checkAddNetworks(_, cb) {
                var uuids = Object.keys(allocateIPs);
                checkNetworks(opts, parsedParams, 'add_networks', uuids, cb);
            },
            function _knownUnknowns(_, cb) {
                if (unknownIPs.length === 0) {
                    cb();
                    return;
                }
                lookupUnknownIPs(opts, ipsField, unknownIPs, parsedParams, cb);
            },
            function temp(_, cb) {
                var a = [];
                for (var network in provisionIPs) {
                    a = a.concat(provisionIPs[network]);
                }
                if (a.length > 0) {
                    parsedParams._ips = (parsedParams._ips || []).concat(a);
                }
                cb();
            }
        ]
    }, callback);
}


function lookupUnknownIP(opts, name, vlan_id, nic_tag, unknownIP, callback) {
    mod_net.findContaining(opts, vlan_id, nic_tag, unknownIP,
        function (err, uuids) {
        if (err) {
            callback(err);
            return;
        }

        if (uuids.length === 0) {
            callback(errors.invalidParam(name,
                util.format(constants.fmt.IP_NONET, nic_tag, vlan_id,
                unknownIP)));
            return;
        }

        if (uuids.length > 1) {
            callback(errors.invalidParam(name,
                util.format(constants.fmt.IP_MULTI, uuids.join(', '),
                unknownIP)));
            return;
        }

        opts.network_cache.get(uuids[0], function (err2, network) {
            if (err2) {
                callback(err2);
                return;
            }

            validateSubnetContainsIP(opts, name, network, unknownIP, callback);
        });
    });
}


function lookupUnknownIPs(opts, name, unknownIPs, parsedParams, callback) {
    // IP specified, but no network UUID: vlan_id and nic_tag are needed to
    // figure out what network the nic is on
    var errs = [];
    ['nic_tag', 'vlan_id'].forEach(function (p) {
        if (!parsedParams.hasOwnProperty(p)) {
            errs.push(errors.missingParam(p, constants.msg.IP_NO_VLAN_TAG));
        }
    });

    if (errs.length !== 0) {
        callback(errs);
        return;
    }

    var vlan_id = parsedParams.vlan_id;
    var nic_tag = parsedParams.nic_tag;

    var ips = [];
    var networks = {};

    function processIP(uip, cb) {
        lookupUnknownIP(opts, name, vlan_id, nic_tag, uip, function (err, ip) {
            if (ip) {
                ips.push(ip);
                networks[ip.params.network.uuid] = true;
            }
            cb(err);
        });
    }

    vasync.forEachPipeline({
        inputs: unknownIPs,
        func: processIP
    }, function (err) {
        if (err) {
            callback(err);
            return;
        }

        networks = Object.keys(networks);
        parsedParams._ips = (parsedParams._ips || []).concat(ips);
        checkNetworks(opts, parsedParams, name, networks, callback);
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
    validateAddIPs: validateAddIPs,
    validateAddNetworks: validateAddNetworks,
    validateMappings: validateMappings,
    validateMAC: validateMAC,
    validateNetwork: validateNetwork,
    validateNetworkParams: validateNetworkParams
};


/*
 * Circular dependencies 'require'd here. DON'T ASK QUESTIONS.
 */
var provision = require('./provision');
