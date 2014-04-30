'use strict';
var internals = {
  defaults: {},
  verify: null
};

exports.register = function (plugin, options, next) {
  internals.error = plugin.hapi.error;
  internals.verify = options.verify;

  plugin.auth.scheme('token-endpoint', internals.scheme);

  next();
};

internals.scheme = function (server, options) {
  return {
    authenticate: internals.authenticate
  };
};

internals.authenticate = function (request, reply) {
  var header,
    parts,
    scheme,
    credentials,
    client,
    secret;

  if (request.headers.authorization) {
    // Find credentials in the header
    authorization = request.headers.authorization;
    parts = authorization.split(' ');
    if (parts.length < 2) {
      return reply('Invalid authorization header.');
    }

    scheme = parts[0];
    credentials = new Buffer(parts[1], 'base64').toString().split(':');
    client = credentials[0];
    secret = credentials[1];
  } else if (request.payload.client_id && request.payload.client_secret) {
    // Find credentials in the body
    client = request.payload.client_id;
    secret = request.payload.client_secret;
  } else {
    return reply('No authorization credentials.');
  }

  if (!client || !secret) {
    return reply('Invalid authorization credentials.');
  }

  internals.verify(client, secret, function (err, user, info) {
    info = info || {};

    if (err) {
      return reply(internals.error.unauthorized(err));
    }

    if (!user) {
      return reply(info.message || 'Unable to verify credentials');
    }

    reply(null, {credentials: user, artifacts: info});
  });
};

