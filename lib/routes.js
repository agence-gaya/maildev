'use strict'

/**
 * MailDev - routes.js
 */
const utils = require('./utils')
const express = require('express')
const compression = require('compression')
const pkg = require('../package.json')
const { filterEmails } = require('./utils')

const emailRegexp = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/

module.exports = function (app, mailserver, basePathname) {
  const router = express.Router()

  // Get all emails
  router.get('/email', compression(), function (req, res) {
    mailserver.getAllEmail(req.headers.host, function (err, emailList) {
      if (err) return res.status(404).json([])
      if (req.query) {
        const filteredEmails = filterEmails(emailList, req.query)
        res.json(filteredEmails)
      } else {
        res.json(emailList)
      }
    })
  })

  // Get single email
  router.get('/email/:id', function (req, res) {
    mailserver.getEmail(req.headers.host, req.params.id, function (err, email) {
      if (err) return res.status(404).json({ error: err.message })

      email.read = true // Mark the email as 'read'

      res.json(email)
    })
  })

  // Read email
  // router.patch('/email/:id/read', function (req, res) {
  //  mailserver.readEmail(req.params.id, function (err, email) {
  //    if (err) return res.status(500).json({ error: err.message })
  //    res.json(true)
  //  })
  // })

  // Read all emails
  router.patch('/email/read-all', function (req, res) {
    mailserver.readAllEmail(req.headers.host, function (err, count) {
      if (err) return res.status(500).json({ error: err.message })
      res.json(count)
    })
  })

  // Delete all emails
  router.delete('/email/all', function (req, res) {
    mailserver.deleteAllEmail(req.headers.host, function (err) {
      if (err) return res.status(500).json({ error: err.message })

      res.json(true)
    })
  })

  // Delete email by id
  router.delete('/email/:id', function (req, res) {
    mailserver.deleteEmail(req.headers.host, req.params.id, function (err) {
      if (err) return res.status(500).json({ error: err.message })

      res.json(true)
    })
  })

  // Get Email HTML
  router.get('/email/:id/html', function (req, res) {
    // Use the headers over hostname to include any port
    const baseUrl = req.headers.host + (req.baseUrl || '')

    mailserver.getEmailHTML(req.headers.host, req.params.id, baseUrl, function (err, html) {
      if (err) return res.status(404).json({ error: err.message })

      res.send(html)
    })
  })

  // Serve Attachments
  router.get('/email/:id/attachment/:filename', function (req, res) {
    mailserver.getEmailAttachment(req.headers.host, req.params.id, req.params.filename, function (err, contentType, readStream) {
      if (err) return res.status(404).json('File not found')

      res.contentType(contentType)
      readStream.pipe(res)
    })
  })

  // Serve email.eml
  router.get('/email/:id/download', function (req, res) {
    mailserver.getEmailEml(req.headers.host, req.params.id, function (err, contentType, filename, readStream) {
      if (err) return res.status(404).json('File not found')

      res.setHeader('Content-disposition', 'attachment; filename=' + filename)
      res.contentType(contentType)
      readStream.pipe(res)
    })
  })

  // Get email source from .eml file
  router.get('/email/:id/source', function (req, res) {
    mailserver.getRawEmail(req.headers.host, req.params.id, function (err, readStream) {
      if (err) return res.status(404).json('File not found')
      readStream.pipe(res)
    })
  })

  // Get any config settings for display
  router.get('/config', function (req, res) {
    res.json({
      version: pkg.version,
      smtpPort: mailserver.port,
      isOutgoingEnabled: mailserver.isOutgoingEnabled(),
      outgoingHost: mailserver.getOutgoingHost()
    })
  })

  // Relay the email
  router.post('/email/:id/relay/:relayTo?', function (req, res) {
    mailserver.getEmail(req.headers.host, req.params.id, function (err, email) {
      if (err) return res.status(404).json({ error: err.message })

      if (req.params.relayTo) {
        if (emailRegexp.test(req.params.relayTo)) {
          email = utils.clone(email)
          email.to = [{ address: req.params.relayTo }]
          email.envelope.to = [{ address: req.params.relayTo, args: false }]
        } else {
          return res.status(400).json({ error: 'Incorrect email address provided :' + req.params.relayTo })
        }
      }

      mailserver.relayMail(req.headers.host, email, function (err) {
        if (err) return res.status(500).json({ error: err.message })

        res.json(true)
      })
    })
  })

  // Health check
  router.get('/healthz', function (req, res) {
    res.json(true)
  })

  router.get('/reloadMailsFromDirectory', function (req, res) {
    mailserver.loadMailsFromDirectory(req.headers.host)
    res.json(true)
  })
  app.use(basePathname, router)
}
