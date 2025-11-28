/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    if (file.includes('\0') || file.includes('%00')) {
      res.status(400).send('Invalid characters in file name.')
      return
    }

    if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
      const safePath = path.resolve('ftp/', file)
      if (!safePath.startsWith(path.resolve('ftp/'))) {
         res.status(403).send('Access denied.')
         return
      }
      res.sendFile(safePath)
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
