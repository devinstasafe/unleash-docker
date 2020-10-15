'use strict'

const unleash = require('unleash-server')
var auth = require('basic-auth')
var axios = require('axios')

unleash
  .start({
    enableLegacyRoutes: false,
    adminAuthentication: 'custom',
    preRouterHook: basicAuthentication
  })
  .then(server => {
    console.log(`Unleash started on http://localhost:${server.app.get('port')}`)
  })

function basicAuthentication (app) {
  app.get('/error', (req, res) => {
    res.send('Error!')
  })
  var check = /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/
  app.use('/api/client/', async (req, res, next) => {
    // console.log(req);
    console.log(req.query)
    let mytoken = null

    // Get token from header or url
    if (check.test(req.header('X-Token'))) {
      mytoken = req.header('X-Token')
    } else if (check.test(req.query.token)) {
      mytoken = req.query.token
    }
    console.log('Token ==> ' + mytoken)

    try {
      if (await isTokenValid(req, mytoken)) {
        next()
      } else {
        res.sendStatus(401)
      }
    } catch (error) {
      console.log(error)
      res.sendStatus(401)
    }
  })

  app.use('/api/admin/', async (req, res, next) => {
    console.log(req.query)
    let mytoken = null
    if (check.test(req.header('X-Token'))) {
      mytoken = req.header('X-Token')
    } else if (check.test(req.query.token)) {
      mytoken = req.query.token
    }

    try {
      if (await isTokenValid(req, mytoken)) {
        next()
      } else {
        const credentials = auth(req)

        if (
          credentials === undefined ||
          credentials.name !== process.env.UNLEASH_MASTER_USERNAME ||
          credentials.pass !== process.env.UNLEASH_MASTER_PASSWORD
        ) {
          return res
            .status('401')
            .set({ 'WWW-Authenticate': 'Basic realm="example"' })
            .end('access denied')
        } else {
          next()
        }
      }
    } catch (error) {}
  })
}

async function isTokenValid (req, mytoken) {
  var VARLIDATEAPI
  if (req.get('host').includes('qa') || req.get('host').includes('dev')) {
    VARLIDATEAPI =
      'https://dev.instasafe.io/console/auth/signin/users/challenge/token'
  }

  if (req.get('host').includes('app')) {
    VARLIDATEAPI =
      'https://app.instasafe.io/console/auth/signin/users/challenge/token'
  }

  var config = {
    method: 'get',
    url: VARLIDATEAPI,
    headers: {
      'x-token': mytoken,
      'Content-Type': 'application/json'
    }
  }
  try {
    var response = await axios(config)
    console.log('response.data.success ==> ' + response.data.success)
    return response.data.success
  } catch (error) {
    console.log(error)
    return false
  }
}
