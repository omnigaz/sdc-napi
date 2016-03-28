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
var mod_vasync = require('vasync');
var mod_nicTag = require('../nic-tag');
var mod_portolan_moray = require('portolan-moray');
var Nic = require('./obj').Nic;
var provision = require('./provision');
var util = require('util');
var util_mac = require('../../util/mac');
var util_common = require('../../util/common');
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
    'network4',
    'network6',
    'network_uuid',
    'network6_uuid',
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
    opts.nic.network4 = opts.validated.network4;
    opts.nic.network6 = opts.validated.network6;

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
            var newNet = newIP.params.network;
            opts.nic.ips.push(newIP);
            opts.batch.push(newIP.batch());
            common.saveNetwork(opts.nic, newNet);
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

    updatedNicParams.etag = opts.existingNic.etag;

    return updatedNicParams;
}



// --- Internal functions in the update chain

/**
 * Get the existing nic from moray
 */
function getExistingNic(opts, callback) {
    opts.log.trace('getExistingNic: entry');

    var macNum = util_mac.macAddressToNumber(opts.params.mac);
    if (!macNum) {
        // Just return here - we'll fail with a nicer error in
        // validateUpdateParams()
        return callback();
    }

    getNic(opts, function (err, res) {
        if (err) {
            return callback(err);
        }

        opts.existingNic = res;
        return callback();
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
            network_uuid: common.validateNetwork.bind(null, opts.app,
                opts.log, 'network4'),
            network6_uuid: common.validateNetwork.bind(null, opts.app,
                opts.log, 'network6'),
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
            // Only add the old IP's network if we're not
            // updating to a new network
            if (opts.existingNic) {
                if (!parsed.hasOwnProperty('network4') &&
                    opts.existingNic.network4 !== null) {
                    parsed.network4 = opts.existingNic.network4;
                    parsed.network_uuid = opts.existingNic.network4.uuid;
                }
                if (!parsed.hasOwnProperty('network6') &&
                    opts.existingNic.network6 !== null) {
                    parsed.network6 = opts.existingNic.network6;
                    parsed.network6_uuid = opts.existingNic.network6.uuid;
                }
            }

            common.validateNetworkParams({ app: opts.app, log: opts.log },
                original, parsed, cb2);
        }
    }, function (err, res) {
        opts.validated = res;

        if (opts.log.debug()) {
            opts.log.debug({ validated: res }, 'validated params');
        }

        return callback(err);
    });
}


/**
 * Determine what sort of update type this is and set opts.updateType
 * accordingly, so that later functions in the update chain can run.
 */
function setUpdateType(opts, callback) {
    opts.log.trace('setUpdateType: entry');

    var oldNic = opts.existingNic;
    var oldIP = oldNic.params.ip;

    opts.updateType = 'update';

    if (!oldIP && opts.validated.network_uuid) {
        // The nic didn't have an IP before, but we want one: let
        // provisionIP() handle
        opts.updateType = 'provision';
        opts.log.debug({ updateType: opts.updateType }, 'update type');
        return callback();
    }

    opts.log.debug({ updateType: opts.updateType }, 'update type');
    return callback();
}


/**
 * If opts.updateType is 'provision', try to provision an IP with the
 * updated nic params
 */
function provisionIP(opts, callback) {
    opts.log.trace('provisionIP: entry');

    if (opts.updateType !== 'provision') {
        return callback();
    }

    opts.nicFn = addUpdatedNic;
    opts.baseParams = mod_ip.params(getUpdatedNicParams(opts));

    var existingIPs = opts.validated._ips;
    var allProvisionable = existingIPs !== undefined && existingIPs.reduce(
        function (acc, curr) { return acc && curr.provisionable(); }, true);

    if (allProvisionable) {
        // We're provisioning existing IPs, and they're all OK to be
        // provisioned: add _provisionableIPs so that provision.ipsOnNetwork()
        // will use it.
        opts._provisionableIPs = existingIPs;
    }

    return provision.nicAndIP(opts, callback);
}

function checkBelongsToUUID(ips, belongs_to_uuid, callback) {
    vasync.forEachPipeline({
        'inputs': ips,
        'func': function (ip, cb) {
            if (ip.params.hasOwnProperty('belongs_to_uuid') &&
                ip.params.belongs_to_uuid !== belongs_to_uuid) {
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

/**
 * If opts.update is 'update', update both the nic and IP. If changing IPs,
 * free the old one (but only if its ownership hasn't changed out from
 * under us).
 */
function updateParams(opts, callback) {
    opts.log.trace('updateParams: entry');

    if (opts.updateType !== 'update') {
        return callback();
    }

    var oldNIC = opts.existingNic;
    var newIPs = opts.validated._ips;
    var oldIPs = oldNIC.ips ? oldNIC.ips : [];
    var addedIPs = [];
    var deltdIPs = [];

    var paramIPs = oldNIC.ips;

    var ip;

    if (newIPs) {
        paramIPs = newIPs;
        for (ip in newIPs) {
            ip = newIPs[ip];
            if (oldIPs.indexOf(ip) === -1) {
                addedIPs.push(ip);
            }
        }

        for (ip in oldIPs) {
            ip = oldIPs[ip];
            if (newIPs.indexOf(ip) === -1) {
                deltdIPs.push(ip);
            }
        }
    }

    var deletingIPs = (deltdIPs.length > 0);

    vasync.pipeline({
        'funcs': [
            function _checkNewIPs(_, cb) {
                checkBelongsToUUID(addedIPs,
                    opts.validated.belongs_to_uuid, cb);
            },
            function _batchNIC(_, cb) {
                // due to poor factoring of create/update operations, updates of
                // type 'update' get the appropriate SVP logs created after the
                // updated nic object is created below. See also Nic.batch.
                opts.vnetCns = [];
                try {
                    addNicAndIPtoBatch(opts, paramIPs);
                } catch (batchErr) {
                    return cb(batchErr);
                }
                cb();
            },
            function _freeOldIPs(_, cb) {
                deltdIPs.forEach(function (oldIP) {
                    if (oldIP.params.belongs_to_uuid ===
                        oldNIC.params.belongs_to_uuid) {
                        opts.batch.push(oldIP.batch({ free: true }));
                    }
                });
                cb();
            },
            // SVP logs must be updated when the MAC:IP mappings change, since
            // the MAC is not updatable, we are only concerned with IP changes.
            // We may need to create logs for one, none, or both of the
            // following situations:
            //   - the existing nic is on a fabric network (requires VL2 logs)
            //   - the updated nic is on a fabric network (requires VL3 logs)
            function _existingVnetCns(_, cb) {
                if (!deletingIPs || !opts.existingNic.isFabric()) {
                    return cb();
                }
                var vnet_id = opts.existingNic.representativeNet().vnet_id;
                common.listVnetCns({
                    vnet_id: vnet_id,
                    moray: opts.app.moray,
                    log: opts.log
                }, function (listErr, cns) {
                    if (listErr) {
                        return cb(listErr);
                    }
                    opts.batch.concat(mod_portolan_moray.vl2CnEventBatch({
                        log: opts.log,
                        vnetCns: cns,
                        vnet_id: vnet_id,
                        mac: opts.existingNic.mac
                    }));
                    return cb();
                });
            },
            function _updatedVnetCns(_, cb) {
                if (!deletingIPs || !opts.nic.isFabric()) {
                    return cb();
                }
                var gennet = opts.existingNic.representativeNet();
                var vnet_id = gennet.vnet_id;
                var vlan_id = gennet.params.vlan_id;
                common.listVnetCns({
                    vnet_id: vnet_id,
                    moray: opts.app.moray,
                    log: opts.log
                }, function (listErr, cns) {
                    if (listErr) {
                        return cb(listErr);
                    }
                    opts.nic.ips.forEach(function (addr) {
                        opts.batch.concat(mod_portolan_moray.vl3CnEventBatch({
                            log: opts.log,
                            vnetCns: cns,
                            vnet_id: vnet_id,
                            ip: addr.v6address,
                            mac: opts.nic.mac,
                            vlan_id: vlan_id
                        }));
                    });
                    return cb();
                });
            }
        ]
    }, function (err, results) {
        if (err) {
            return callback(err);
        }
        return common.commitBatch(opts, callback);
    });
}


// --- Exports


/**
 * Updates a nic with the given parameters
 */
function update(opts, callback) {
    opts.log.trace('nic.update: entry');

    var funcs = [
        function _existingNic(_opts, _cb) {
            getNic(_opts, function (err, nic) {
                _opts.existingNic = nic;
                return _cb(err);
            });
        },
        validateUpdateParams,
        setUpdateType,
        provisionIP,
        updateParams
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
