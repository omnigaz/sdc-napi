/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2016, Joyent, Inc.
 */

/*
 * nic model: updating
 */

'use strict';

var assert = require('assert-plus');
var common = require('./common');
var constants = require('../../util/constants');
var errors = require('../../util/errors');
var getNic = require('./get').get;
var mod_ip = require('../ip');
var mod_net = require('../network');
var mod_nicTag = require('../nic-tag');
var Nic = require('./obj').Nic;
var provision = require('./provision');
var util = require('util');
var util_ip = require('../../util/ip');
var vasync = require('vasync');
var validate = require('../../util/validate');



// --- GLOBALS



// Updatable nic params
var UPDATE_PARAMS = [
    'allow_dhcp_spoofing',
    'allow_ip_spoofing',
    'allow_mac_spoofing',
    'allow_restricted_traffic',
    'allow_unfiltered_promisc',
    'belongs_to_type',
    'belongs_to_uuid',
    'check_owner',
    'cn_uuid',
    'ip',
    'owner_uuid',
    'model',
    'network_uuid',
    'nic_tag',
    'nic_tags_provided',
    'primary',
    'reserved',
    'state',
    'vlan_id'
];



// --- Internal helpers



/**
 * Uses the updated parameters to create a new nic object in opts.nic and
 * add it to opts.batch
 */
function addUpdatedNic(opts, callback) {
    try {
        opts.nic = new Nic(getUpdatedNicParams(opts));
    } catch (nicErr) {
        // XXX: wrap this error with WError
        return callback(nicErr);
    }

    opts.nic.ips = opts.ips;

    return callback();
}


/**
 * Used the updated parameters in opts.validated to create a new opts.nic
 * and opts.ip, and adds them to opts.batch
 */
function addNicAndIPtoBatch(opts, ipObjs) {
    try {
        opts.nic = new Nic(getUpdatedNicParams(opts));
    } catch (nicErr) {
        // XXX: wrap this error with WError
        throw nicErr;
    }

    if (ipObjs) {
        // Use the new nic's params to populate the new IP: this ensures
        // it gets any updated parameters
        opts.nic.ips = [];
        ipObjs.forEach(function (ipObj) {
            var newIP = mod_ip.createUpdated(ipObj, opts.nic.params);
            opts.nic.ips.push(newIP);
            opts.batch.push(newIP.batch());
        });
    }

    provision.addNicToBatch(opts);
}


/**
 * Returns an object of the updatable nic params from opts.validated
 */
function getUpdatedNicParams(opts) {
    var updatedNicParams = opts.existingNic.serialize();

    UPDATE_PARAMS.forEach(function (p) {
        if (opts.validated.hasOwnProperty(p)) {
            updatedNicParams[p] = opts.validated[p];
        }
    });

    if (updatedNicParams.hasOwnProperty('ip')) {
        updatedNicParams.ip = util_ip.aton(updatedNicParams.ip.toString());
    }

    updatedNicParams.etag = opts.existingNic.etag;

    return updatedNicParams;
}



// --- Internal functions in the update chain

/**
 * Get the existing nic from moray
 */
function getExistingNic(opts, callback) {
    opts.log.trace('getExistingNic: entry');

    getNic(opts, function (err, res) {
        opts.existingNic = res;
        return callback(err);
    });
}

/**
 * Validate a nic tag that may potentially be an overlay tag (of the form
 * sdc_overlay_tag/1234)
 */
function validateNicTag(opts, name, tag, callback) {
    validate.string(name, tag, function (strErr) {
        if (strErr) {
            return callback(strErr);
        }

        var split = tag.split('/');
        var tagName = split[0];

        mod_nicTag.validateExists(opts.app, opts.log, true, name, tagName,
                function (exErr) {
            if (exErr) {
                return callback(exErr);
            }

            if (!split[1]) {
                return callback(null, tagName);
            }

            validate.VxLAN(name, split[1], function (vErr, vid) {
                if (vErr) {
                    return callback(vErr);
                }

                var toReturn = {};
                toReturn[name] = tagName;
                toReturn.vnet_id = vid;

                return callback(null, null, toReturn);
            });
        });
    });
}

/**
 * Validate update params
 */
function validateUpdateParams(opts, callback) {
    opts.log.trace('validateUpdateParams: entry');

    var uopts = {
        app: opts.app,
        create: false,
        log: opts.log,
        network_cache: new mod_net.NetworkCache(opts.app, opts.log)
    };

    validate.params({
        params: opts.params,

        required: {
            mac: common.validateMAC
        },

        optional: {
            // XXX: allow passing an optional arg to validate.params(), so
            // that we can pass opts to these fns as an arg. This would allow
            // us to move this object up to top-level (replacing UPDATE_PARAMS),
            // so that we don't have to duplicate these
            add_ips: common.validateAddIPs.bind(null, uopts),
            add_networks: common.validateAddNetworks.bind(null, uopts),
            allow_dhcp_spoofing: validate.bool,
            allow_ip_spoofing: validate.bool,
            allow_mac_spoofing: validate.bool,
            allow_restricted_traffic: validate.bool,
            allow_unfiltered_promisc: validate.bool,
            belongs_to_type: validate.string,
            belongs_to_uuid: validate.UUID,
            check_owner: validate.bool,
            cn_uuid: validate.UUID,
            ip: validate.IPv4,
            ips: validate.PrefixedIPs,
            owner_uuid: validate.UUID,
            model: validate.string,
            network_uuid: common.validateNetwork.bind(null, uopts),
            network_uuids: common.validateMappings.bind(null, uopts),
            nic_tag: validateNicTag.bind(null, opts),
            nic_tags_provided:
                mod_nicTag.validateExists.bind(null, opts.app, opts.log,
                    false),
            primary: validate.bool,
            reserved: validate.bool,
            state: validate.nicState,
            // XXX: only allow this if belongs_to_type is 'server'
            underlay: validate.bool,
            vlan_id: validate.VLAN
        },

        after: function (original, parsed, cb2) {
            assert.ok(opts.existingNic, 'existingNic');
            var oldNIC = opts.existingNic;

            if (oldNIC.params.hasOwnProperty('vlan_id')) {
                if (parsed.hasOwnProperty('vlan_id') &&
                    oldNIC.params.vlan_id !== parsed.vlan_id) {
                    cb2(errors.invalidParam('vlan_id', 'Immutable'));
                    return;
                } else {
                    parsed.vlan_id = oldNIC.params.vlan_id;
                }
            }

            if (oldNIC.params.hasOwnProperty('nic_tag')) {
                if (parsed.hasOwnProperty('nic_tag') &&
                    oldNIC.params.nic_tag !== parsed.nic_tag) {
                    cb2(errors.invalidParam('nic_tag', 'Immutable'));
                    return;
                } else {
                    parsed.nic_tag = oldNIC.params.nic_tag;
                }
            }

            if (!parsed.hasOwnProperty('ips') &&
                !parsed.hasOwnProperty('ip') && oldNIC.ips !== null) {
                parsed._ips = oldNIC.ips;
            }

            common.validateNetworkParams(uopts, original, parsed, cb2);
        }
    }, function (err, res) {
        opts.validated = res;

        if (opts.log.debug()) {
            opts.log.debug({ validated: res }, 'validated params');
        }

        return callback(err);
    });
}

function v6address(ip) {
    return ip.v6address;
}

/**
 * Provision any new IPs that we need, free old ones, and update NIC properties.
 */
function prepareUpdate(opts, callback) {

    opts.log.trace('provisionIP: entry');

    opts.nicFn = addUpdatedNic;
    opts.baseParams = mod_ip.params(getUpdatedNicParams(opts));

    if (!opts.validated.hasOwnProperty('_ips')) {
        callback();
        return;
    }

    var oldNIC = opts.existingNic;
    var oldIPs = oldNIC.ips !== null ? oldNIC.ips : [];
    var nicOwner = oldNIC.params.belongs_to_uuid;

    var ips = opts.validated._ips;

    // If all IPs that we're adding are okay to use, then we'll want to do
    // an update of the IP records. We add _provisionableIPs so that
    // provision.ipsOnNetwork() will use it.
    opts._provisionableIPs = ips;
    opts._removeIPs = [];

    var newAddrs = ips.map(v6address);
    var oldAddrs = oldIPs.map(v6address);

    oldIPs.forEach(function (oldIP) {
        // Avoid freeing if IP ownership has changed underneath us.
        if (newAddrs.indexOf(oldIP.v6address) === -1 &&
            nicOwner === oldIP.params.belongs_to_uuid) {
            opts._removeIPs.push(oldIP);
        }
    });

    vasync.forEachPipeline({
        'inputs': ips.filter(function (newIP) {
            return (oldAddrs.indexOf(newIP.v6address) === -1);
        }),
        'func': function (ip, cb) {
            if (!ip.provisionable()) {
                var oldUsedErr = new errors.InvalidParamsError(
                    constants.msg.INVALID_PARAMS, [ errors.usedByParam('ip',
                        ip.params.belongs_to_type, ip.params.belongs_to_uuid,
                        util.format(constants.fmt.IP_IN_USE,
                            ip.params.belongs_to_type,
                            ip.params.belongs_to_uuid))
                    ]);
                oldUsedErr.stop = true;
                return cb(oldUsedErr);
            }
            return cb();
        }
    }, callback);
}


// --- Exports


/**
 * Updates a nic with the given parameters
 */
function update(opts, callback) {
    opts.log.trace('nic.update: entry');

    var funcs = [
        getExistingNic,
        validateUpdateParams,
        prepareUpdate,
        provision.nicAndIP
    ];

    opts.batch = [];

    vasync.pipeline({
        arg: opts,
        funcs: funcs
    }, function (err) {
        if (err) {
            opts.log.error({
                before: opts.existingNic ?
                    opts.existingNic.serialize() : '<does not exist>',
                err: err,
                params: opts.validated
            }, 'Error updating nic');

            return callback(err);
        }

        opts.log.info({
            before: opts.existingNic.serialize(),
            params: opts.validated,
            after: opts.nic.serialize()
        }, 'Updated nic');

        return callback(null, opts.nic);
    });
}



module.exports = {
    update: update
};
