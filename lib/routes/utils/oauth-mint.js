/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

const jwtool = require('fxa-jwtool')
const Pool = require('../../pool')

// From the Firefox source code:
// Having this parameter be short has limited security value and can cause
// spurious authentication values if the client's clock is skewed and
// we fail to adjust. See Bug 983256.
const ASSERTION_LIFETIME = 1000 * 3600 * 24 * 365 * 25 // 25 years in ms.
const CERT_LIFETIME      = 1000 * 3600 * 5 // 5 hours in ms.

const CLIENT_ID = '5882386c6d801776' // Desktop CLIENT_ID, is this ok?

module.exports = (config, signer)  => {
  const secretKey = jwtool.JWK.fromFile(config.secretKeyFile)
  const publicKey = jwtool.JWK.fromFile(config.publicKeyFile)
  const pool = new Pool(config.oauth.url, { timeout: 1000 })
  return {
    getOAuthToken(sessionToken, scope) {
      return this.generateOAuthAssertion(sessionToken)
        .then(assertion => {
          return pool.post('/v1/authorization', {
            assertion,
            client_id: CLIENT_ID,
            response_type: 'token',
            scope
          })
        })
    },
    generateOAuthAssertion(sessionToken) {
      return signer.sign({
        publicKey: publicKey.toJSON(),
        email: `${sessionToken.uid.toString('hex')}@${config.domain}`,
        domain: config.domain,
        duration: CERT_LIFETIME,
        generation: sessionToken.verifierSetAt,
        lastAuthAt: sessionToken.lastAuthAt(),
        verifiedEmail: sessionToken.email,
      }).then(res => {
        return secretKey.sign({
          exp: Date.now() + ASSERTION_LIFETIME,
          aud: `${config.oauth.url}/v1`
        })
        .then(assertion => `${res.cert}~${assertion}`)
      })
    }
  }
}
