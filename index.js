
'use strict'

/**
 * Unleash server implementation which supports Github Authentication
 * and access control. Only members of the specified domain are
 * allowed to sign up.
 *
 * The implementation assumes the following environment variables:
 * - DATABASE_URL
 * - GITHUB_CLIENT_ID
 * - GITHUB_CLIENT_SECRET
 * - GITHUB_CALLBACK_URL
 * - WHITELISTED_DOMAIN
 */

const fs = require('fs')
const unleash = require('unleash-server')
const passport = require('@passport-next/passport')
const GitHubStrategy = require('passport-github')
    .Strategy
const fetch = require('node-fetch');

const { User, AuthenticationRequired } = unleash

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

passport.use(
    new GitHubStrategy(
        {
            clientID: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            callbackURL: process.env.GITHUB_CALLBACK_URL
        },
        (accessToken, refreshToken, profile, done) => {
            fetch('https://api.github.com/user/orgs', {
                method: 'get',
                headers: { 'Authorization': `Bearer ${accessToken}` },
            })
                .then(res => res.json())
                .then(orgs => {
                    console.log(orgs)
                    let isSixgillMember = false;

                    orgs.forEach(org => {
                        if (org.login === "sixgill") {
                            isSixgillMember = true;
                        }
                    });

                    if (isSixgillMember === false) {
                        done(
                            "unauthorized user",
                            null)
                    } else {
                        done(
                            null,
                            new User({
                                name: profile.displayName,
                                email: `${profile.login}@sixgill.com`
                            })
                        )
                    }
                });
        }
    )
)

function enableGoogleOauth(app) {
    app.use(passport.initialize())
    app.use(passport.session())

    passport.serializeUser((user, done) => done(null, user))
    passport.deserializeUser((user, done) => done(null, user))
    app.get(
        '/api/admin/login',
        passport.authenticate('github', { scope: ['read:org'] })
    )

    app.get(
        '/api/auth/callback',
        passport.authenticate('github', {
            failureRedirect: '/api/admin/error-login'
        }),
        (req, res) => {
            // Successful authentication, redirect to your app.
            res.redirect('/')
        }
    )

    app.use('/api/admin/', (req, res, next) => {
        const whitelistRegex = new RegExp(
            '@' + escapeRegExp(process.env.WHITELISTED_DOMAIN) + '$'
        )

        if (req.user) {
            if (whitelistRegex.test(req.user.email)) {
                next()
            } else {
                return res
                    .status('401')
                    .json(
                        new AuthenticationRequired({
                            path: '/api/admin/login',
                            type: 'custom',
                            message: 'You don\'t have permission to access this dashboard.'
                        })
                    )
                    .end()
            }
        } else {
            // Instruct unleash-frontend to pop-up auth dialog
            return res
                .status('401')
                .json(
                    new AuthenticationRequired({
                        path: '/api/admin/login',
                        type: 'custom',
                        message: `You have to identify yourself in order to use Unleash. 
            Click the button and follow the instructions.`
                    })
                )
                .end()
        }
    })

    app.use('/api/client', (req, res, next) => {
        if (req.header('authorization') !== process.env.CLIENT_API_PSK) {
            res.sendStatus(401);
        } else {
            next();
        }
    });
}

const options = {
    adminAuthentication: null,
    preRouterHook: enableGoogleOauth
}

unleash.start(options)