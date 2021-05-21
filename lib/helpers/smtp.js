'use strict'

const wildstring = require('wildstring')

const smtpHelpers = module.exports = {}

/**
 * Authorize callback for smtp server
 */
smtpHelpers.createOnAuthCallback = function (username, password) {
  return function onAuth (auth, session, callback) {
    if (auth.username && auth.password) {
      if (auth.username !== username || auth.password !== password) {
        return callback(new Error('Invalid username or password'))
      }
    }
    callback(null, { user: username })
  }
}

/**
 * Validate domain with rules
 */
function validateDomainRules (rules, domain) {
  if (!rules) {
    return true
  }

  return rules.reduce(function (result, rule) {
    const toMatch = rule.allow || rule.deny || ''
    const isMatch = wildstring.match(toMatch, domain)

    // Override previous rule if it matches
    return isMatch ? (!!rule.allow) : result
  }, true)
}

/**
 * Filter based on HELO/EHLO hostname
 */
smtpHelpers.createOnMailFromValidateDomainCallback = function (rules) {
  return function onMailFrom (address, session, callback) {

    if (!rules) {
      return callback()
    }

    if (!session.hostNameAppearsAs || !validateDomainRules(rules, session.hostNameAppearsAs)) {
      return callback(new Error("Your are not allowed to send mail"))
    }

    return callback()
  }
}

