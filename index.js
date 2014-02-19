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
  var authorization = request.headers.authorization,
    parts,
    scheme,
    credentials,
    client,
    secret;

  if (!authorization) {
    return reply('No authorization header.');
  }

  parts = authorization.split(' ');
  if (parts.length < 2) {
    return reply('Invalid authorization header.');
  }

  scheme = parts[0];
  credentials = new Buffer(parts[1], 'base64').toString().split(':');

  client = credentials[0];
  secret = credentials[1];

  if (!client || !secret) {
    return reply('Invalid authorization header.');
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

