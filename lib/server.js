/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

const fs = require('fs')
const Hapi = require('hapi')
const Raven = require('raven')
const path = require('path')
const url = require('url')
const userAgent = require('./userAgent')

const { HEX_STRING } = require('./routes/validators')

function trimLocale(header) {
  if (! header) {
    return header
  }
  if (header.length < 256) {
    return header.trim()
  }
  var parts = header.split(',')
  var str = parts[0]
  if (str.length >= 255) { return null }
  for (var i = 1; i < parts.length && str.length + parts[i].length < 255; i++) {
    str += ',' + parts[i]
  }
  return str.trim()
}

function logEndpointErrors(response, log) {
  // When requests to DB timeout and fail for unknown reason they are an 'EndpointError'.
  // The error response hides error information from the user, but we log it here
  // to better understand the DB timeouts.
  if (response.__proto__ && response.__proto__.name === 'EndpointError') {
    var endpointLog = {
      op: 'server.EndpointError',
      message: response.message,
      reason: response.reason
    }
    if (response.attempt && response.attempt.method) {
      // log the DB attempt to understand the action
      endpointLog.method = response.attempt.method
    }
    log.error(endpointLog)
  }
}

function create(log, error, config, routes, db, translator) {
  const getGeoData = require('./geodb')(log)

  // Hawk needs to calculate request signatures based on public URL,
  // not the local URL to which it is bound.
  var publicURL = url.parse(config.publicUrl)
  var defaultPorts = {
    'http:': 80,
    'https:': 443
  }
  var hawkOptions = {
    host: publicURL.hostname,
    port: publicURL.port ? publicURL.port : defaultPorts[publicURL.protocol],

    // We're seeing massive clock skew in deployed clients, and it's
    // making auth harder than it needs to be.  This effectively disables
    // the timestamp checks by setting it to a humongous value.
    timestampSkewSec: 20 * 365 * 24 * 60 * 60,  // 20 years, +/- a few days

    nonceFunc: function nonceCheck(key, nonce, ts, cb) {
      // Since we've disabled timestamp checks, there's not much point
      // keeping a nonce cache.  Instead we use this as an opportunity
      // to report on the clock skew values seen in the wild.
      var skew = (Date.now() / 1000) - (+ts)
      log.trace({ op: 'server.nonceFunc', skew: skew })
      return cb()
    }
  }

  function makeCredentialFn(dbGetFn) {
    return function (id, cb) {
      log.trace({ op: 'DB.getToken', id: id })
      if (! HEX_STRING.test(id)) {
        return process.nextTick(cb.bind(null, null, null)) // not found
      }
      dbGetFn(id)
        .then(token => {
          if (token.expired(Date.now())) {
            const err = error.invalidToken('The authentication token has expired')

            if (token.tokenTypeID === 'sessionToken') {
              return db.pruneSessionTokens(token.uid, [ token ])
                .catch(() => {})
                .then(() => cb(err))
            }

            return cb(err)
          }

          return cb(null, token)
        }, cb)
    }
  }

  var serverOptions = {
    connections: {
      routes: {
        cors: {
          additionalExposedHeaders: ['Timestamp', 'Accept-Language'],
          origin: config.corsOrigin
        },
        security: {
          hsts: {
            maxAge: 15552000,
            includeSubdomains: true
          }
        },
        state: {
          parse: false
        },
        payload: {
          maxBytes: 16384
        },
        files: {
          relativeTo: path.dirname(__dirname)
        },
        validate: {
          options: {
            stripUnknown: true
          }
        }
      },
      load: {
        maxEventLoopDelay: config.maxEventLoopDelay
      }
    },
    load: {
      sampleInterval: 1000
    },
    useDomains: true
  }

  var connectionOptions = {
    host: config.listen.host,
    port: config.listen.port
  }

  if (config.useHttps) {
    connectionOptions.tls = {
      key: fs.readFileSync(config.keyPath),
      cert: fs.readFileSync(config.certPath)
    }
  }

  var server = new Hapi.Server(serverOptions)

  // register 'inert' to support service static files
  server.register(require('inert'), function () {
    // callback required
  })

  server.connection(connectionOptions)

  if (config.hpkpConfig && config.hpkpConfig.enabled) {
    var hpkpOptions = {
      maxAge: config.hpkpConfig.maxAge,
      sha256s: config.hpkpConfig.sha256s,
      includeSubdomains: config.hpkpConfig.includeSubDomains
    }

    if (config.hpkpConfig.reportUri){
      hpkpOptions.reportUri = config.hpkpConfig.reportUri
    }

    if (config.hpkpConfig.reportOnly){
      hpkpOptions.reportOnly = config.hpkpConfig.reportOnly
    }

    server.register({
      register: require('hapi-hpkp'),
      options: hpkpOptions
    }, function (err) {
      if (err) {
        throw err
      }
    })
  }

  server.register(require('hapi-auth-hawk'), function (err) {
    if (err) {
      throw err
    }

    server.auth.strategy(
      'sessionToken',
      'hawk',
      {
        getCredentialsFunc: makeCredentialFn(db.sessionToken.bind(db)),
        hawk: hawkOptions
      }
    )
    server.auth.strategy(
      'keyFetchToken',
      'hawk',
      {
        getCredentialsFunc: makeCredentialFn(db.keyFetchToken.bind(db)),
        hawk: hawkOptions
      }
    )
    server.auth.strategy(
      // This strategy fetches the keyFetchToken with its
      // verification state. It doesn't check that state.
      'keyFetchTokenWithVerificationStatus',
      'hawk',
      {
        getCredentialsFunc: makeCredentialFn(db.keyFetchTokenWithVerificationStatus.bind(db)),
        hawk: hawkOptions
      }
    )
    server.auth.strategy(
      'accountResetToken',
      'hawk',
      {
        getCredentialsFunc: makeCredentialFn(db.accountResetToken.bind(db)),
        hawk: hawkOptions
      }
    )
    server.auth.strategy(
      'passwordForgotToken',
      'hawk',
      {
        getCredentialsFunc: makeCredentialFn(db.passwordForgotToken.bind(db)),
        hawk: hawkOptions
      }
    )
    server.auth.strategy(
      'passwordChangeToken',
      'hawk',
      {
        getCredentialsFunc: makeCredentialFn(db.passwordChangeToken.bind(db)),
        hawk: hawkOptions
      }
    )

    server.register(require('hapi-fxa-oauth'), function (err) {
      if (err) {
        throw err
      }

      server.auth.strategy('oauthToken', 'fxa-oauth', config.oauth)

      // routes should be registered after all auth strategies have initialized:
      // ref: http://hapijs.com/tutorials/auth
      server.route(routes)
    })
  })

  server.ext('onRequest', (request, reply) => {
    log.begin('server.onRequest', request)
    reply.continue()
  })

  server.ext('onPreAuth', (request, reply) => {
    defineLazyGetter(request.app, 'remoteAddressChain', () => {
      const xff = (request.headers['x-forwarded-for'] || '').split(/\s*,\s*/)

      xff.push(request.info.remoteAddress)

      return xff.map(address => address.trim()).filter(address => !! address)
    })

    defineLazyGetter(request.app, 'clientAddress', () => {
      const remoteAddressChain = request.app.remoteAddressChain
      let clientAddressIndex = remoteAddressChain.length - (config.clientAddressDepth || 1)

      if (clientAddressIndex < 0) {
        clientAddressIndex = 0
      }

      return remoteAddressChain[clientAddressIndex]
    })

    defineLazyGetter(request.app, 'acceptLanguage', () => trimLocale(request.headers['accept-language']))
    defineLazyGetter(request.app, 'locale', () => translator.getLocale(request.app.acceptLanguage))

    defineLazyGetter(request.app, 'ua', () => userAgent(request.headers['user-agent']))
    defineLazyGetter(request.app, 'geo', () => getGeoData(request.app.clientAddress))

    defineLazyGetter(request.app, 'devices', () => {
      let uid

      if (request.auth && request.auth.credentials) {
        uid = request.auth.credentials.uid
      } else if (request.payload && request.payload.uid) {
        uid = request.payload.uid
      }

      return db.devices(uid)
    })

    if (request.headers.authorization) {
      // Log some helpful details for debugging authentication problems.
      log.trace({
        op: 'server.onPreAuth',
        rid: request.id,
        path: request.path,
        auth: request.headers.authorization,
        type: request.headers['content-type'] || ''
      })
    }

    reply.continue()
  })

  server.ext('onPreHandler', (request, reply) => {
    const features = request.payload && request.payload.features
    request.app.features = new Set(Array.isArray(features) ? features : [])

    reply.continue()
  })

  server.ext('onPreResponse', (request, reply) => {
    let response = request.response
    if (response.isBoom) {
      logEndpointErrors(response, log)
      response = error.translate(response)
      if (config.env !== 'prod') {
        response.backtrace(request.app.traced)
      }
    }
    response.header('Timestamp', '' + Math.floor(Date.now() / 1000))
    log.summary(request, response)
    reply(response)
  })

  // configure Sentry
  const sentryDsn = config.sentryDsn
  if (sentryDsn) {
    Raven.config(sentryDsn, {})
    server.on('request-error', function (request, err) {
      let exception = ''
      if (err && err.stack) {
        try {
          exception = err.stack.split('\n')[0]
        } catch (e) {
          // ignore bad stack frames
        }
      }

      Raven.captureException(err, {
        extra: {
          exception: exception
        }
      })
    })
  }

  const metricsContext = require('./metrics/context')(log, config)
  server.decorate('request', 'stashMetricsContext', metricsContext.stash)
  server.decorate('request', 'gatherMetricsContext', metricsContext.gather)
  server.decorate('request', 'clearMetricsContext', metricsContext.clear)
  server.decorate('request', 'validateMetricsContext', metricsContext.validate)
  server.decorate('request', 'setMetricsFlowCompleteSignal', metricsContext.setFlowCompleteSignal)

  const metricsEvents = require('./metrics/events')(log, config)
  server.decorate('request', 'emitMetricsEvent', metricsEvents.emit)
  server.decorate('request', 'emitRouteFlowEvent', metricsEvents.emitRouteFlowEvent)

  server.stat = function() {
    return {
      stat: 'mem',
      rss: server.load.rss,
      heapUsed: server.load.heapUsed
    }
  }

  return server
}

function defineLazyGetter (object, key, getter) {
  let value
  Object.defineProperty(object, key, {
    get () {
      if (! value) {
        value = getter()
      }

      return value
    }
  })
}

module.exports = {
  create: create,
  // Functions below exported for testing
  _trimLocale: trimLocale,
  _logEndpointErrors: logEndpointErrors
}
