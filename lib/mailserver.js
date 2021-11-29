'use strict'

/**
 * MailDev - mailserver.js
 */

const SMTPServer = require('smtp-server').SMTPServer
const MailParser = require('../vendor/mailparser-mit').MailParser
const events = require('events')
const fs = require('fs')
const os = require('os')
const path = require('path')
const rimraf = require('rimraf')
const utils = require('./utils')
const logger = require('./logger')
const timers = require('timers')
const smtpHelpers = require('./helpers/smtp')
const { calculateBcc } = require('./helpers/bcc')
const outgoing = require('./outgoing')
const createDOMPurify = require('dompurify')
const { JSDOM } = require('jsdom')

const eventEmitter = new events.EventEmitter()

const defaultPort = 1025
const defaultHost = '0.0.0.0'
const defaultMailDir = path.join(
  os.tmpdir(),
  `maildev-${process.pid.toString()}`
)

/**
 * Mail Server exports
 */

const mailServer = (module.exports = {})

mailServer.store = {}

/**
 * SMTP Server stream and helper functions
 */

// Save an email object on stream end
function saveEmailToStore (id, isRead = false, envelope, parsedEmail) {
  const host = envelope.host
  const emlPath = path.join(mailServer.virtualDir(host), id + '.eml')

  const stat = fs.statSync(emlPath)

  // serialize attachments without stream object
  const serializedAttachments =
    parsedEmail.attachments && parsedEmail.attachments.length
      ? parsedEmail.attachments.map((attachment) => {
          const { stream, ...remaining } = attachment
          return remaining
        })
      : null

  const { attachments, ...parsedEmailRemaining } = parsedEmail

  const serialized = utils.clone(parsedEmailRemaining)

  serialized.id = id
  serialized.time = parsedEmail.date ? parsedEmail.date : envelope.date ? envelope.date : new Date()
  serialized.read = isRead
  serialized.envelope = envelope
  serialized.source = emlPath
  serialized.size = stat.size
  serialized.sizeHuman = utils.formatBytes(stat.size)
  serialized.attachments = serializedAttachments
  const onlyAddress = (xs) => (xs || []).map((x) => x.address)
  serialized.calculatedBcc = calculateBcc(
    onlyAddress(envelope.to),
    onlyAddress(parsedEmail.to),
    onlyAddress(parsedEmail.cc)
  )

  mailServer.virtualStore(host).push(serialized)

  if (envelope.init) {
  	return
  }

  logger.log('Saving email: %s, id: %s', parsedEmail.subject, id)

  if (outgoing.isAutoRelayEnabled()) {
    mailServer.relayMail(host, serialized, true, function (err) {
      if (err) logger.error('Error when relaying email', err)
    })
  }

  eventEmitter.emit('new', mailServer.virtualHostEnabled ? mailServer.virtualHost(host) : false, serialized)
}

// Save an attachment
function saveAttachment (host, id, attachment) {
  var attachmentDir = path.join(mailServer.virtualDir(host), id)
  if (!fs.existsSync(attachmentDir)) {
    fs.mkdirSync(attachmentDir)
  }
  const output = fs.createWriteStream(
    path.join(attachmentDir, attachment.contentId)
  )
  attachment.stream.pipe(output)
}

/**
 * Handle smtp-server onData stream
 */
function handleDataStream (stream, session, callback) {
  const id = utils.makeId()

  const envelope = {
    from: session.envelope.mailFrom,
    to: session.envelope.rcptTo,
    host: session.hostNameAppearsAs,
    remoteAddress: session.remoteAddress
  }

  fs.writeFileSync(path.join(mailServer.virtualDir(session.hostNameAppearsAs), id + '.evl'), JSON.stringify(envelope), 'utf-8');

  const emlStream = fs.createWriteStream(
    path.join(mailServer.virtualDir(session.hostNameAppearsAs), id + '.eml')
  )
  emlStream.on('open', function () {
    const parseStream = new MailParser({
      streamAttachments: true
    })

    parseStream.on('end', saveEmailToStore.bind(null, id, false, envelope))
    parseStream.on('attachment', saveAttachment.bind(null, session.hostNameAppearsAs, id))

    stream.pipe(emlStream)
    stream.pipe(parseStream)

    stream.on('end', function () {
      emlStream.end()
      callback(null, 'Message queued as ' + id)
    })
  })
}

/**
 * Delete everything in the mail directory
 */
function clearMailDir (host) {
  const mailDir = mailServer.virtualDir(host)
  fs.readdir(mailDir, function (err, files) {
    if (err) throw err

    files.forEach(function (file) {
      rimraf(path.join(mailDir, file), function (err) {
        if (err) throw err
      })
    })
  })
}

/**
 * Create mail directory
 */

function createMailDir () {
  if (!fs.existsSync(mailServer.mailDir)) {
    fs.mkdirSync(mailServer.mailDir)
  }
  logger.info('MailDev using directory %s', mailServer.mailDir)
}

/**
 * Load Domain Filter Rules file
 */

function loadDomainFilterRules (file) {
  let rules = false
  if (typeof file === 'string') {
    try {
      rules = JSON.parse(fs.readFileSync(file, 'utf8'))
    } catch (err) {
      logger.error('Error reading config file at ' + file)
      throw err
    }
    logger.info('Domain filter mode on, Domain rules: ' + JSON.stringify(rules))
  }

  return rules
}

/**
 * Create and configure the mailserver
 */

mailServer.create = function (
  port,
  host,
  mailDir,
  virtualHostEnabled,
  user,
  password,
  hideExtensions,
  domainFilterRulesFile,
  isSecure,
  certFilePath,
  keyFilePath
) {
  mailServer.mailDir = mailDir || defaultMailDir
  mailServer.virtualHostEnabled = virtualHostEnabled

  if (mailServer.virtualHostEnabled) {
    logger.info('Virtual-Host mode on, the view of emails depends on the domain')
  }

  createMailDir()

  const hideExtensionOptions = getHideExtensionOptions(hideExtensions)
  const smtpServerConfig = Object.assign(
    {
      secure: isSecure,
      cert: certFilePath ? fs.readFileSync(certFilePath) : null,
      key: keyFilePath ? fs.readFileSync(keyFilePath) : null,
      onAuth: smtpHelpers.createOnAuthCallback(user, password),
      onMailFrom: smtpHelpers.createOnMailFromValidateDomainCallback(loadDomainFilterRules(domainFilterRulesFile)),
      onData: handleDataStream,
      logger: false,
      hideSTARTTLS: true,
      disabledCommands: user && password ? (isSecure ? [] : ['STARTTLS']) : ['AUTH']
    },
    hideExtensionOptions
  )

  const smtp = new SMTPServer(smtpServerConfig)

  smtp.on('error', mailServer.onSmtpError)

  mailServer.port = port || defaultPort
  mailServer.host = host || defaultHost

  // testability requires this to be exposed.
  // otherwise we cannot test whether error handling works
  mailServer.smtp = smtp
}

const HIDEABLE_EXTENSIONS = [
  'STARTTLS', // Keep it for backward compatibility, but is overriden by hardcoded `hideSTARTTLS`
  'PIPELINING',
  '8BITMIME',
  'SMTPUTF8'
]

function getHideExtensionOptions (extensions) {
  if (!extensions) {
    return {}
  }
  return extensions.reduce(function (options, extension) {
    const ext = extension.toUpperCase()
    if (HIDEABLE_EXTENSIONS.indexOf(ext) > -1) {
      options[`hide${ext}`] = true
    } else {
      throw new Error(`Invalid hideable extension: ${ext}`)
    }
    return options
  }, {})
}

/**
 * Start the mailServer
 */

mailServer.listen = function (callback) {
  if (typeof callback !== 'function') callback = null

  // Listen on the specified port
  mailServer.smtp.listen(mailServer.port, mailServer.host, function (err) {
    if (err) {
      if (callback) {
        callback(err)
      } else {
        throw err
      }
    }

    if (callback) callback()

    logger.info(
      'MailDev SMTP Server running at %s:%s',
      mailServer.host,
      mailServer.port
    )
  })
}

/**
 * Handle mailServer error
 */

mailServer.onSmtpError = function (err) {
  if (err.code === 'ECONNRESET' && err.syscall === 'read') {
    logger.warn(
      `Ignoring "${err.message}" error thrown by SMTP server. Likely the client connection closed prematurely. Full error details below.`
    )
    logger.error(err)
  } else throw err
}

/**
 * Stop the mailserver
 */

mailServer.close = function (callback) {
  mailServer.emit('close')
  mailServer.smtp.close(callback)
  outgoing.close()
}

/**
 * Extend Event Emitter methods
 * events:
 *   'new' - emitted when new email has arrived
 */

mailServer.on = eventEmitter.on.bind(eventEmitter)
mailServer.emit = eventEmitter.emit.bind(eventEmitter)
mailServer.removeListener = eventEmitter.removeListener.bind(eventEmitter)
mailServer.removeAllListeners =
  eventEmitter.removeAllListeners.bind(eventEmitter)

/**
 * Empty all virtual store
 */
mailServer.emptyAllVirtualStore = function () {
  mailServer.store = {}
}

/**
 * Return virtual host from host name that may include port
 */

mailServer.virtualHost = function (host) {
  return host.split(':')[0]
}

/**
 * Return store array for host name
 */

mailServer.virtualStore = function (host) {
  const vhost = mailServer.virtualHostEnabled ? mailServer.virtualHost(host) : '__common__'
  if (! mailServer.store[vhost]) {
    mailServer.store[vhost] = []
  }
  return mailServer.store[vhost]
}

/**
 * Return virtual directory from host name
 */

mailServer.virtualDir = function (host) {
  const virtualDir = path.join(mailServer.mailDir, mailServer.virtualHost(host))
  if (!fs.existsSync(virtualDir)) {
    fs.mkdirSync(virtualDir)
  }
  return virtualDir
}

/**
 * Return virtual host name from directory name
 */

mailServer.virtualHostFromDir = function (dir) {
  return dir
}

/**
 * Get an email by id
 */

mailServer.getEmail = function (host, id, done) {
  const email = mailServer.virtualStore(host).filter(function (element) {
    return element.id === id
  })[0]

  if (email) {
    if (email.html) {
      // sanitize html
      const window = new JSDOM('').window
      const DOMPurify = createDOMPurify(window)
      email.html = DOMPurify.sanitize(email.html, {
        WHOLE_DOCUMENT: true, // preserve html,head,body elements
        SANITIZE_DOM: false, // ignore DOM cloberring to preserve form id/name attributes
        ADD_TAGS: ['link'], // allow link element to preserve external style sheets
        ADD_ATTR: ['target'] // Preserve explicit target attributes on links
      })
    }
    done(null, email)
  } else {
    done(new Error('Email was not found'))
  }
}

/**
 * Returns a readable stream of the raw email
 */

mailServer.getRawEmail = function (host, id, done) {
  mailServer.getEmail(host, id, function (err, email) {
    if (err) return done(err)

    done(null, fs.createReadStream(path.join(mailServer.virtualDir(host), id + '.eml')))
  })
}

/**
 * Returns the html of a given email
 */

mailServer.getEmailHTML = function (host, id, baseUrl, done) {
  if (!done && typeof baseUrl === 'function') {
    done = baseUrl
    baseUrl = null
  }

  if (baseUrl) {
    baseUrl = '//' + baseUrl
  }

  mailServer.getEmail(host, id, function (err, email) {
    if (err) return done(err)

    let html = email.html

    if (!email.attachments) {
      return done(null, html)
    }

    const embeddedAttachments = email.attachments.filter(function (attachment) {
      return attachment.contentId
    })

    const getFileUrl = function (id, baseUrl, filename) {
      return (
        (baseUrl || '') +
        '/email/' +
        id +
        '/attachment/' +
        encodeURIComponent(filename)
      )
    }

    if (embeddedAttachments.length) {
      embeddedAttachments.forEach(function (attachment) {
        const regex = new RegExp(
          "src=(\"|')cid:" + attachment.contentId + "(\"|')",
          'g'
        )
        const replacement =
          'src="' + getFileUrl(id, baseUrl, attachment.generatedFileName) + '"'
        html = html.replace(regex, replacement)
      })
    }

    done(null, html)
  })
}

/**
 * Read all emails
 */
mailServer.readAllEmail = function (host, done) {
  const allUnread = mailServer.virtualStore(host).filter(function (element) {
    return !element.read
  })
  for (const email of allUnread) {
    email.read = true
  }
  done(null, allUnread.length)
}

/**
 * Get all email
 */
mailServer.getAllEmail = function (host, done) {
  done(null, mailServer.virtualStore(host))
}

/**
 * Delete an email by id
 */

mailServer.deleteEmail = function (host, id, done) {
  let email = null
  let emailIndex = null
  const store = mailServer.virtualStore(host)
  store.forEach(function (element, index) {
    if (element.id === id) {
      email = element
      emailIndex = index
    }
  })

  if (emailIndex === null) {
    return done(new Error('Email not found'))
  }

  // delete raw envelope
  fs.unlink(path.join(mailServer.virtualDir(host), id + '.evl'), function (err) {
    if (err) {
      logger.error(err)
    } else {
      eventEmitter.emit('delete', mailServer.virtualHostEnabled ? mailServer.virtualHost(host) : false, { id: id, index: emailIndex })
    }
  })

  // delete raw email
  fs.unlink(path.join(mailServer.virtualDir(host), id + '.eml'), function (err) {
    if (err) {
      logger.error(err)
    }
  })

  // delete attachment
  if (email.attachments) {
    rimraf(path.join(mailServer.virtualDir(host), id), function (err) {
      if (err) {
        logger.error(err)
      }
    })
  }

  logger.warn('Deleting email %s - %s', mailServer.virtualHost(host), email.subject)

  store.splice(emailIndex, 1)

  done(null, true)
}

/**
 * Trigger each hours a delete of email older than delay in hours
 */
mailServer.setAutoDelete = function (delay) {
  if (delay > 0) {
    timers.setInterval(function () { mailServer.deleteOldEmail(delay * 3600000) }, 3600000)
  }
}

/**
 * Delete emails older than delay in microseconds
 */
mailServer.deleteOldEmail = function (delay) {
  const expired = new Date().getTime() - delay
  for (var host in mailServer.store) {
    mailServer.store[host].forEach(function (element, index) {
      if (element.time < expired) {
        mailServer.deleteEmail(host, element.id, function () {})
      }
    })
  }
}

/**
 * Delete all emails in the store
 */

mailServer.deleteAllEmail = function (host, done) {
  logger.warn('Deleting all email of %s', mailServer.virtualHost(host))

  clearMailDir(host)

  mailServer.virtualStore(host).length = 0

  eventEmitter.emit('delete', mailServer.virtualHostEnabled ? mailServer.virtualHost(host) : false, { id: 'all' })

  done(null, true)
}

/**
 * Returns the content type and a readable stream of the file
 */

mailServer.getEmailAttachment = function (host, id, filename, done) {
  mailServer.getEmail(host, id, function (err, email) {
    if (err) return done(err)

    if (!email.attachments || !email.attachments.length) {
      return done(new Error('Email has no attachments'))
    }

    const match = email.attachments.filter(function (attachment) {
      return attachment.generatedFileName === filename
    })[0]

    if (!match) {
      return done(new Error('Attachment not found'))
    }

    done(
      null,
      match.contentType,
      fs.createReadStream(path.join(mailServer.virtualDir(host), id, match.contentId))
    )
  })
}

/**
 * Setup outgoing
 */
mailServer.setupOutgoing = function (host, port, user, pass, secure) {
  outgoing.setup(host, port, user, pass, secure)
}

mailServer.isOutgoingEnabled = function () {
  return outgoing.isEnabled()
}

mailServer.getOutgoingHost = function () {
  return outgoing.getOutgoingHost()
}

/**
 * Set Auto Relay Mode, automatic send email to recipient
 */

mailServer.setAutoRelayMode = function (enabled, rules, emailAddress) {
  outgoing.setAutoRelayMode(enabled, rules, emailAddress)
}

/**
 * Relay a given email, accepts a mail id or a mail object
 */

mailServer.relayMail = function (host, idOrMailObject, isAutoRelay, done) {
  if (!outgoing.isEnabled()) {
    return done(new Error('Outgoing mail not configured'))
  }

  // isAutoRelay is an option argument
  if (typeof isAutoRelay === 'function') {
    done = isAutoRelay
    isAutoRelay = false
  }

  // If we receive a email id, get the email object
  if (typeof idOrMailObject === 'string') {
    mailServer.getEmail(host, idOrMailObject, function (err, mail) {
      if (err) return done(err)
      mailServer.relayMail(host, mail, isAutoRelay, done)
    })
    return
  }

  const mail = idOrMailObject

  mailServer.getRawEmail(host, mail.id, function (err, rawEmailStream) {
    if (err) {
      logger.error('Mail Stream Error: ', err)
      return done(err)
    }

    outgoing.relayMail(mail, rawEmailStream, isAutoRelay, done)
  })
}

/**
 * Download a given email
 */

mailServer.getEmailEml = function (host, id, done) {
  mailServer.getEmail(host, id, function (err, email) {
    if (err) return done(err)

    const filename = email.id + '.eml'

    done(
      null,
      'message/rfc822',
      filename,
      fs.createReadStream(path.join(mailServer.virtualDir(host), id + '.eml'))
    )
  })
}

/**
 * Import email from directory in store
 */

mailServer.loadMailsFromDirectory = function () {
  const persistencePath = fs.realpathSync(mailServer.mailDir)
  fs.readdir(persistencePath, function (err, dirs) {
    if (err) {
      logger.error('Error during reading of the mailDir %s', persistencePath)
      return
    }

      mailServer.emptyAllVirtualStore()

      dirs.forEach(function (dir) {
        if (fs.lstatSync(path.join(persistencePath, dir)).isDirectory() && dir != '.' && dir != '..') {
          fs.readdir(path.join(persistencePath, dir), function (err, files) {
            if (err) {
              logger.error('Scanning mail directory failed: %s', err)
              return
            }

          files.forEach(function (file) {
            const filePath = path.join(persistencePath, dir, file)
            if (path.parse(file).ext === '.evl') {
              fs.readFile(filePath, 'utf8', function(err, data) {
                if (err) {
                  logger.error('Loading envelope failed: %s', err)
                  return
                }
                const filePath = path.join(persistencePath, dir, path.parse(file).name + '.eml')
                const host = mailServer.virtualHostFromDir(dir)
                const envelope = JSON.parse(data)
                envelope.host = host
                envelope.date = fs.statSync(filePath).ctime
                envelope.init = true

                fs.readFile(filePath, 'utf8', function (err, data) {
                  if (err) {
                    logger.error('Loading mail failed: %s', err)
                    return
                  }

                  const idMail = path.parse(file).name

                  const parseStream = new MailParser({
                    streamAttachments: true
                  })

                  parseStream.on('end', function (mail) {
                    saveEmailToStore(idMail, true, envelope, mail)
                  })

                  parseStream.on('attachment', saveAttachment.bind(null, host, idMail))

                  parseStream.write(data)
                  parseStream.end()
                })
              })
            }
          })
        })
      }
    })
  })
}
