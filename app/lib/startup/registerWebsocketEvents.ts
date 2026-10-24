/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { Server } from 'socket.io'
import { notifications, challenges } from '../../data/datacache'
import * as challengeUtils from '../challengeUtils'
import * as security from '../insecurity'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  io: Server
}

const registerWebsocketEvents = (server: any) => {
  const io = new Server(server, { cors: { origin: 'http://localhost:4200' } })
  /* Security headers for socket.io's own HTTP responses (local change, phase 8 F5; see app/VENDORED.md).
     engine.io answers /socket.io/ before Express, so helmet never runs there. This must come AFTER
     new Server(): engine.io and socket.io replace all 'request' listeners when they attach. */
  server.prependListener('request', (req: any, res: any) => {
    if (req.url?.startsWith('/socket.io/')) {
      res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
      res.setHeader('X-Content-Type-Options', 'nosniff')
      res.setHeader('X-Frame-Options', 'DENY')
    }
  })
  globalWithSocketIO.io = io

  io.on('connection', (socket: any) => {
    if (firstConnectedSocket === null) {
      socket.emit('server started')
      firstConnectedSocket = socket.id
    }

    notifications.forEach((notification: any) => {
      socket.emit('challenge solved', notification)
    })

    socket.on('notification received', (data: any) => {
      const i = notifications.findIndex(({ flag }: any) => flag === data)
      if (i > -1) {
        notifications.splice(i, 1)
      }
    })

    socket.on('verifyLocalXssChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.localXssChallenge, () => { return data?.includes('<iframe src="javascript:alert(`xss`)">') ?? false })
      challengeUtils.solveIf(challenges.xssBonusChallenge, () => { return data?.includes(config.get('challenges.xssBonusPayload')) ?? false })
    })

    socket.on('verifySvgInjectionChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.svgInjectionChallenge, () => { return data?.match(/.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/cataas.com\/cat.*/) && security.isRedirectAllowed(data) })
    })

    socket.on('verifyCloseNotificationsChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => { return Array.isArray(data) && data.length > 1 })
    })
  })
}

export default registerWebsocketEvents
