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
    authenticate: internals.authenticate,
    payload: internals.payload
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
    authorization = request.headers.authorization;
    parts = authorization.split(' ');
    if (parts.length < 2) {
      return reply('Invalid authorization header.');
    }

    scheme = parts[0];
    credentials = new Buffer(parts[1], 'base64').toString().split(':');
    client = credentials[0];
    secret = credentials[1];

    if (!client || !secret) {
      return reply('Invalid authorization credentials.');
    }

    reply(null, internals.process(client, secret));
  } else {
    reply(null, {credentials: 'deferred'})
  } 

};

internals.payload = function (request, next) {
  var client, secret, response;

  if (request.auth.credentials === 'deferred' && request.payload.client_id && request.payload.client_secret) {
    client = request.payload.client_id;
    secret = request.payload.client_secret;
  } else {
    return next(false);
  }
  
  response = internals.process(client, secret);

  if (response instanceof Error) {
    return next(response);
  }

  if (response instanceof String) {
    return next(response);
  }

  if (!response.credentials) {
    return next(false);
  }
  
  next();
}

internals.process = function (client, secret) {
  internals.verify(client, secret, function (err, user, info) {
    info = info || {};

    if (err) {
      return internals.error.unauthorized(err);
    }

    if (!user) {
      return info.message || 'Unable to verify credentials';
    }

    return {credentials: user, artifacts: info};
  });
}
