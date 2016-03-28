/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2016, Joyent, Inc.
 */

/*
 * NAPI /networks/:network_uuid/nics endpoints
 */

var errors = require('../../util/errors');
var mod_net = require('../../models/network');
var mod_nic = require('../../models/nic');
var mod_pool = require('../../models/network-pool');
var reqToOpts = require('../../util/common').reqToOpts;



// --- Endpoints



/**
 * POST /networks/:network_uuid/nics: create a nic on a logical network
 */
function postNetworkNic(req, res, next) {
    var opts = reqToOpts(req);

    function doCreate() {
        mod_nic.create(opts,
            function (err, nic) {
            if (err) {
                return next(err);
            }
            res.send(200, nic.serialize());
            return next();
        });
    }

    /* If an IPv6 network is specified, don't try to move network_uuid */
    if (opts.params.hasOwnProperty('network6_uuid')) {
        return doCreate();
    }

    /* We check the type of the network in case we need to move the UUID */

    var netOpts = {
            app: opts.app,
            log: opts.log,
            params: { uuid: opts.params.network_uuid }
    };

    function notFound() {
        return next(errors.invalidParam('network_uuid',
            'network does not exist'));
    }

    function handle404(onErr, onSuccess) {
        return function (err, net) {
            if (err) {
                if (err.name === 'ResourceNotFoundError') {
                    onErr();
                    return;
                }

                next(err);
                return;
            }

            switch (net.type) {
            case 'ipv6':
                opts.params.network6_uuid = net.uuid;
                delete opts.params.network_uuid;
                break;
            case 'ipv4':
                break;
            default:
                return next(errors.invalidParam('network_uuid',
                    'network is of unknown address family'));
            }

            doCreate();
        };
    }

    mod_net.get(netOpts, handle404(function getPool() {
        mod_pool.get(opts.app, opts.log, netOpts.params, handle404(notFound));
    }));
}


/**
 * Register all endpoints with the restify server
 */
function register(http, before) {
    http.post(
        { path: '/networks/:network_uuid/nics', name: 'ProvisionNic' },
        before, postNetworkNic);
}



module.exports = {
    register: register
};
