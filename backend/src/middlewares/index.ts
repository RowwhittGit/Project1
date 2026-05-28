import express from 'express';
import jwt from 'jsonwebtoken';
import Tokens from 'csrf';
import lodash from 'lodash';

import User from "../models/userModel.js";
import * as cookiesSettings from '../constants/v1AuthenticationCookiesSettings.js';
import * as errorCodes from '../constants/v1AuthenticationErrorCodes.js';

export function isAuthenticated(req: express.Request, res: express.Response, next: express.NextFunction): any {
    const authenticationToken: string = req.cookies[cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME];
    const csrfToken: any = req.cookies[cookiesSettings.COOKIE_CSRF_TOKEN_NAME];
    const tokens = new Tokens();

    if (authenticationToken == null) {
        if (!tokens.verify(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string, csrfToken)) {
            const newCsrfToken: any = tokens.create(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string);
            res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, newCsrfToken, {
                httpOnly: true, secure: true, sameSite: 'none', path: '/',
                expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
            });
        }
        return res.status(401).json({ message: 'Invalid Credential.', errorCode: errorCodes.NO_JWT_TOKEN_AUTHENTICATE_JWT_TOKEN });
    }

    jwt.verify(authenticationToken, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, async (error: any, authenticatedUser: any): Promise<any> => {
        if (error) {
            res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, 'expiredtoken', {
                httpOnly: true, secure: true, sameSite: 'none', path: '/', expires: new Date(0)
            });
            const newCsrfToken: any = tokens.create(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string);
            res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, newCsrfToken, {
                httpOnly: true, secure: true, sameSite: 'none', path: '/',
                expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
            });
            return res.status(403).json({ message: 'Invalid Credential.', errorCode: errorCodes.INVALID_JWT_TOKEN_AUTHENTICATE_JWT_TOKEN });
        }

        let existingUser = await User.findOne({ _id: authenticatedUser._id })
            .select('-username -email -isSSO -createdAt -updatedAt')
            .populate('profile', '-fullName -profilePicture -createdAt -updatedAt')
            .populate('csrfTokenSecret');

        if (!existingUser) return res.status(404).json({ message: "Invalid Credential.", errorCode: errorCodes.NO_USER_FOUND_IN_DATABASE_INSIDE_JWT_DECODED_TOKEN_AUTHENTICATE_JWT_TOKEN });

        if (!tokens.verify(existingUser.csrfTokenSecret.secret, csrfToken)) {
            res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, 'expiredtoken', {
                httpOnly: true, secure: true, sameSite: 'none', path: '/', expires: new Date(0)
            });
            const newCsrfToken: any = tokens.create(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string);
            res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, newCsrfToken, {
                httpOnly: true, secure: true, sameSite: 'none', path: '/',
                expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
            });
            return res.status(403).json({ message: 'Invalid Credential.', errorCode: errorCodes.INVALID_CSRF_TOKEN_VERIFY_PRIVATE_CSRF_TOKEN });
        }

        existingUser.csrfTokenSecret = undefined;
        lodash.merge(req, { authenticatedUser: existingUser });
        next();
    });
}

export function verifyPublicCSRFToken(req: express.Request, res: express.Response, next: express.NextFunction): any {
    const csrfToken: any = req.cookies[cookiesSettings.COOKIE_CSRF_TOKEN_NAME];
    const tokens = new Tokens();

    if (csrfToken == null) {
        const newCsrfToken: any = tokens.create(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string);
        res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, newCsrfToken, {
            httpOnly: true, secure: true, sameSite: 'none', path: '/',
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });
        return res.status(401).json({ message: 'Invalid Credential.', errorCode: errorCodes.NO_CSRF_TOKEN_VERIFY_PUBLIC_CSRF_TOKEN });
    }

    if (!tokens.verify(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string, csrfToken)) {
        const newCsrfToken: any = tokens.create(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string);
        res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, newCsrfToken, {
            httpOnly: true, secure: true, sameSite: 'none', path: '/',
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });
        return res.status(403).json({ message: 'Invalid Credential.', errorCode: errorCodes.INVALID_CSRF_TOKEN_VERIFY_PUBLIC_CSRF_TOKEN });
    }

    next();
}

export function sendPublicCSRFTokenToUser(req: express.Request, res: express.Response, next: express.NextFunction): any {
    const existingCsrfToken = req.cookies[cookiesSettings.COOKIE_CSRF_TOKEN_NAME];
    if (existingCsrfToken == null) {
        const tokens = new Tokens();
        const csrfToken = tokens.create(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string);
        res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, {
            httpOnly: true, secure: true, sameSite: 'none', path: '/',
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });
    }
    next();
}
