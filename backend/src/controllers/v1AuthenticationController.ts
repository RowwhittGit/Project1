import express from 'express';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import Tokens from 'csrf';
import xss from 'xss';
import mongoSanitize from 'express-mongo-sanitize';
import lodash from 'lodash';
import { OAuth2Client } from 'google-auth-library';

const client = new OAuth2Client();

import User from '../models/userModel.js';
import Profile from '../models/profileModel.js';
import CSRFTokenSecret from '../models/csrfTokenSecretModel.js';

import sendEmail from '../utils/sendEmail.js';
import ErrorResponse from '../utils/ErrorResponse.js';
import tryCatch from '../utils/tryCatch.js';
import generateRandomPasswordSSO from '../utils/generateRandomPasswordSSO.js';
import generateRandomUsernameSSO from '../utils/generateRandomUsernameSSO.js';
import * as validations from '../utils/v1AuthenticationValidations.js';

import * as emailTemplates from '../constants/v1AuthenticationEmailTemplates.js';
import * as errorCodes from '../constants/v1AuthenticationErrorCodes.js';
import * as cookiesSettings from '../constants/v1AuthenticationCookiesSettings.js';
import * as jwtTokensSettings from '../constants/v1AuthenticationJWTTokensSettings.js';
import * as userSettings from '../constants/v1AuthenticationUserSettings.js';

import * as TYPES from '../types/index.js';

const user = tryCatch(async (req: express.Request, res: express.Response) => {
    let authenticatedUser = lodash.get(req, 'authenticatedUser') as unknown as any;
    authenticatedUser = await User.findOne({ _id: authenticatedUser._id })
        .select('-_id -createdAt -updatedAt')
        .populate('profile', '-_id -createdAt -updatedAt');
    return res.status(200).json({ status: 'ok', user: authenticatedUser });
});

const deleteUser = tryCatch(async (req: express.Request, res: express.Response) => {
    const authenticatedUser = lodash.get(req, 'authenticatedUser') as unknown as any;
    const userOwner = await User.findOne({ _id: authenticatedUser._id }).lean();
    if (!userOwner) throw new ErrorResponse(401, 'User does not exist.', errorCodes.USER_NOT_EXIST_DELETE_USER);

    await Profile.findOneAndDelete({ user_id: userOwner._id });
    await CSRFTokenSecret.findOneAndDelete({ user_id: userOwner._id });
    await User.findOneAndDelete({ _id: userOwner._id });

    const tokens = new Tokens();
    const csrfToken = tokens.create(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string);

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, 'expiredtoken', {
        httpOnly: true, secure: true, sameSite: 'none', path: '/', expires: new Date(0)
    });
    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
    });

    return res.status(200).json({ status: 'ok' });
});

const register = tryCatch(async (req: express.Request, res: express.Response) => {
    let { username, email, password, repeatPassword, fullName } = mongoSanitize.sanitize(req.body);
    if (!username || !email || !password || !repeatPassword || !fullName)
        throw new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM);

    username = xss(username); email = xss(email); password = xss(password);
    repeatPassword = xss(repeatPassword); fullName = xss(fullName);

    const { error } = validations.registerValidate(username, email, password, repeatPassword, fullName);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER);

    if (await User.findOne({ username })) throw new ErrorResponse(400, "Username already exist.", errorCodes.USERNAME_EXIST_REGISTER);
    if (await User.findOne({ email })) throw new ErrorResponse(400, "Email already exist.", errorCodes.EMAIL_EXIST_REGISTER);

    const ACCOUNT_ACTIVATION_TOKEN = jwt.sign(
        { username, email, password, repeatPassword, fullName },
        process.env["ACCOUNT_ACTIVATION_TOKEN_SECRET"] as string,
        { expiresIn: jwtTokensSettings.JWT_REGISTER_ACCOUNT_ACTIVATION_EXPIRES_IN_STRING }
    );
    const activateAccountURL = `${process.env["REACT_URL"] as string}/activate/${ACCOUNT_ACTIVATION_TOKEN}`;

    await sendEmail({
        to: email,
        subject: emailTemplates.ACCOUNT_ACTIVATION_EMAIL_SUBJECT,
        text: emailTemplates.ACCOUNT_ACTIVATION_EMAIL_TEXT,
        html: emailTemplates.ACCOUNT_ACTIVATION_EMAIL_HTML(username, activateAccountURL),
    });

    return res.status(200).json({ status: 'ok' });
});

const activate = tryCatch(async (req: express.Request, res: express.Response) => {
    let { token } = mongoSanitize.sanitize(req.body);
    if (!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_ACCOUNT_ACTIVATION_JWT_TOKEN);

    jwt.verify(token, process.env["ACCOUNT_ACTIVATION_TOKEN_SECRET"] as string, (error: any, decoded: any) => {
        if (error) throw new ErrorResponse(401, "Expired link or Invalid Credential. Please sign up again.", errorCodes.EXPIRED_ACCOUNT_ACTIVATION_JWT_TOKEN_OR_INVALID_ACCOUNT_ACTIVATION_JWT_TOKEN);
        token = decoded;
    });

    let { username, email, password, repeatPassword, fullName } = mongoSanitize.sanitize(token);
    if (!username || !email || !password || !repeatPassword || !fullName)
        throw new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM_ACTIVATE);

    username = xss(username); email = xss(email); password = xss(password);
    repeatPassword = xss(repeatPassword); fullName = xss(fullName);

    const { error } = validations.activateValidate(username, email, password, repeatPassword, fullName);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER_ACTIVATE);

    if (await User.findOne({ username })) throw new ErrorResponse(400, "Account has already been activated.", errorCodes.USERNAME_EXIST_REGISTER_ACTIVATE);
    if (await User.findOne({ email })) throw new ErrorResponse(400, "Account has already been activated.", errorCodes.EMAIL_EXIST_REGISTER_ACTIVATE);

    const tokens = new Tokens();
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({ secret: csrfTokenSecret });
    const savedProfile = await Profile.create({ fullName, profilePicture: userSettings.DEFAULT_PROFILE_PICTURE });
    const savedUser = await User.create({
        username, email, password,
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id]
    });

    await CSRFTokenSecret.findOneAndUpdate({ _id: savedCSRFTokenSecret._id }, { user_id: savedUser._id });
    await Profile.findOneAndUpdate({ _id: savedProfile._id }, { user_id: savedUser._id });

    const authenticationToken = jwt.sign({ _id: savedUser._id }, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, { expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING });

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });
    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    return res.status(200).json({ status: 'ok' });
});

const login = tryCatch(async (req: express.Request, res: express.Response) => {
    let { username, password } = mongoSanitize.sanitize(req.body);
    if (!username || !password) throw new ErrorResponse(400, "Please complete the Login form.", errorCodes.INCOMPLETE_LOGIN_FORM);

    username = xss(username); password = xss(password);

    const { error } = validations.loginValidate(username, password);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_LOGIN);

    const existingUser = await User.findOne({ username }).select('+password').populate('csrfTokenSecret');
    if (!existingUser) throw new ErrorResponse(401, 'Invalid username.', errorCodes.USERNAME_NOT_EXIST_LOGIN);

    const isMatched = await existingUser.matchPasswords(password);
    if (!isMatched) throw new ErrorResponse(401, 'Invalid password.', errorCodes.PASSWORD_NOT_MATCH_LOGIN);

    if (existingUser.isSSO) throw new ErrorResponse(401, 'This is an SSO account.', errorCodes.USER_SSO_ACCOUNT_LOGIN);

    const tokens = new Tokens();
    const csrfToken = tokens.create(existingUser.csrfTokenSecret.secret);
    const authenticationToken = jwt.sign({ _id: existingUser._id }, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, { expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING });

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });
    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    return res.status(200).json({ status: 'ok' });
});

const logout = tryCatch(async (req: express.Request, res: express.Response) => {
    const csrfToken = new Tokens().create(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string);

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, 'expiredtoken', {
        httpOnly: true, secure: true, sameSite: 'none', path: '/', expires: new Date(0)
    });
    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
    });

    return res.status(200).json({ status: 'ok' });
});

const forgotPassword = tryCatch(async (req: express.Request, res: express.Response) => {
    let { email } = mongoSanitize.sanitize(req.body);
    if (!email) throw new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM);

    email = xss(email);

    const { error } = validations.forgotPasswordValidate(email);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD);

    const existingUser = await User.findOne({ email }).populate('csrfTokenSecret');
    if (!existingUser) throw new ErrorResponse(400, "Email does not exist.", errorCodes.EMAIL_NOT_EXIST_FORGOT_PASSWORD);
    if (existingUser.isSSO) throw new ErrorResponse(401, 'This is an SSO account.', errorCodes.USER_SSO_ACCOUNT_FORGOT_PASSWORD);

    await User.findOneAndUpdate({ email }, { forgotPassword: true });

    const tokens = new Tokens();
    const csrfToken = tokens.create(existingUser.csrfTokenSecret.secret);
    const CSRF_TOKEN = jwt.sign({ csrfToken }, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET"] as string, { expiresIn: jwtTokensSettings.JWT_ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING });
    const RESET_TOKEN = jwt.sign({ email }, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET"] as string, { expiresIn: jwtTokensSettings.JWT_ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING });

    const resetURL = `${process.env["REACT_URL"] as string}/reset-password/${RESET_TOKEN}/${CSRF_TOKEN}`;

    await sendEmail({
        to: email,
        subject: emailTemplates.RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_SUBJECT,
        text: emailTemplates.RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_TEXT,
        html: emailTemplates.RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_HTML(existingUser.username, resetURL),
    });

    return res.status(200).json({ status: 'ok' });
});

const resetPassword = tryCatch(async (req: express.Request, res: express.Response) => {
    let { token, csrfToken, password, repeatPassword } = mongoSanitize.sanitize(req.body);
    if (!token || !csrfToken) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_RESET_PASSWORD);

    jwt.verify(csrfToken, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET"] as string, (error: any, decoded: any) => {
        if (error) throw new ErrorResponse(401, "Expired link or Invalid Credential.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_RESET_PASSWORD);
        csrfToken = decoded;
    });
    jwt.verify(token, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET"] as string, (error: any, decoded: any) => {
        if (error) throw new ErrorResponse(401, "Expired link or Invalid Credential.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_RESET_PASSWORD);
        token = decoded;
    });

    let { email } = mongoSanitize.sanitize(token);
    const csrfTokenObj = mongoSanitize.sanitize(csrfToken);

    if (!email || !password || !repeatPassword) throw new ErrorResponse(400, "Please complete the Reset Password Form.", errorCodes.INCOMPLETE_RESET_PASSWORD_FORM);
    if (password !== repeatPassword) throw new ErrorResponse(400, "Passwords do not match.", errorCodes.PASSWORD_REPEAT_PASSWORD_NOT_MATCH_RESET_PASSWORD_FORM);

    email = xss(email); password = xss(password); repeatPassword = xss(repeatPassword);

    const { error } = validations.resetPasswordValidate(email, password, repeatPassword);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_RESET_PASSWORD);

    const existingUser = await User.findOne({ email }).populate('csrfTokenSecret');
    if (!existingUser) throw new ErrorResponse(400, "Email does not exist.", errorCodes.EMAIL_NOT_EXIST_RESET_PASSWORD);
    if (existingUser.isSSO) throw new ErrorResponse(401, 'This is an SSO account.', errorCodes.USER_SSO_ACCOUNT_RESET_PASSWORD);

    const tokens = new Tokens();
    if (!tokens.verify(existingUser.csrfTokenSecret.secret, csrfTokenObj.csrfToken))
        throw new ErrorResponse(403, "Invalid Credential.", errorCodes.INVALID_CSRF_TOKEN_RESET_PASSWORD);

    const hashedPassword = await argon2.hash(password);
    await User.findOneAndUpdate({ email }, { password: hashedPassword, forgotPassword: false });

    return res.status(200).json({ status: 'ok' });
});

const accountRecoveryResetPasswordVerifyToken = tryCatch(async (req: express.Request, res: express.Response) => {
    let { token, csrfToken } = mongoSanitize.sanitize(req.body);
    if (!token || !csrfToken) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    jwt.verify(csrfToken, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET"] as string, (error: any, decoded: any) => {
        if (error) throw new ErrorResponse(401, "Expired link or Invalid Credential.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
        csrfToken = decoded;
    });
    jwt.verify(token, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET"] as string, (error: any, decoded: any) => {
        if (error) throw new ErrorResponse(401, "Expired link or Invalid Credential.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
        token = decoded;
    });

    let { email } = mongoSanitize.sanitize(token);
    const csrfTokenObj = mongoSanitize.sanitize(csrfToken);

    if (!email) throw new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    email = xss(email);

    const { error } = validations.accountRecoveryResetPasswordVerifyTokenValidate(email);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    const existingUser = await User.findOne({ email, forgotPassword: true }).populate('csrfTokenSecret');
    if (!existingUser) throw new ErrorResponse(400, "Email does not exist or no password reset was requested.", errorCodes.EMAIL_NOT_EXIST_OR_USER_NOT_REQUEST_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    const tokens = new Tokens();
    if (!tokens.verify(existingUser.csrfTokenSecret.secret, csrfTokenObj.csrfToken))
        throw new ErrorResponse(403, "Invalid Credential.", errorCodes.INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    return res.status(200).json({ status: 'ok' });
});

const ssoSignInGoogleIdentityServices = tryCatch(async (req: express.Request, res: express.Response) => {
    const { token } = mongoSanitize.sanitize(req.body);
    if (!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_SSO_JWT_TOKEN_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);

    const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_IDENITY_SERVICES_CLIENT_ID
    }).catch(() => { throw new ErrorResponse(401, "Failed to sign in. Please try again.", errorCodes.FAILED_VALIDATION_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES); });

    const payload = ticket.getPayload();
    if (!payload) throw new ErrorResponse(401, "Failed to sign in. Please try again.", errorCodes.PAYLOAD_UNDEFINED_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);

    let { email, name } = payload as TYPES.SSO_GOOGLE_IDENTITY_SERVICES_TOKEN_DECODED;
    if (!email || !name) throw new ErrorResponse(400, "Credential must have email and name.", errorCodes.INCOMPLETE_CREDENTIAL_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);

    email = xss(email); name = xss(name);

    const { error } = validations.ssoGoogleIdentityServicesValidate(email, name);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);

    const existingUser = await User.findOne({ email }).populate('csrfTokenSecret');
    if (!existingUser) throw new ErrorResponse(401, 'User does not exist. Please sign up.', errorCodes.USER_NOT_EXIST_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);

    const tokens = new Tokens();
    const csrfToken = tokens.create(existingUser.csrfTokenSecret.secret);
    const authenticationToken = jwt.sign({ _id: existingUser._id }, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, { expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING });

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });
    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    return res.status(200).json({ status: 'ok' });
});

const ssoSignUpGoogleIdentityServices = tryCatch(async (req: express.Request, res: express.Response) => {
    const { token } = mongoSanitize.sanitize(req.body);
    if (!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_SSO_JWT_TOKEN_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);

    const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_IDENITY_SERVICES_CLIENT_ID
    }).catch(() => { throw new ErrorResponse(401, "Failed to sign up. Please try again.", errorCodes.FAILED_VALIDATION_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES); });

    const payload = ticket.getPayload();
    if (!payload) throw new ErrorResponse(401, "Failed to sign up. Please try again.", errorCodes.PAYLOAD_UNDEFINED_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);

    let { email, name } = payload as TYPES.SSO_GOOGLE_IDENTITY_SERVICES_TOKEN_DECODED;
    if (!email || !name) throw new ErrorResponse(400, "Credential must have email and name.", errorCodes.INCOMPLETE_CREDENTIAL_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);

    email = xss(email); name = xss(name);

    const { error } = validations.ssoGoogleIdentityServicesValidate(email, name);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);

    if (await User.findOne({ email })) throw new ErrorResponse(401, 'User already exists.', errorCodes.USER_ALREADY_EXIST_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);

    const tokens = new Tokens();
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({ secret: csrfTokenSecret });
    const savedProfile = await Profile.create({ fullName: name, profilePicture: userSettings.DEFAULT_PROFILE_PICTURE });
    const savedUser = await User.create({
        username: name.split(" ")[0] + "_" + generateRandomUsernameSSO(),
        email,
        password: generateRandomPasswordSSO(),
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id],
        isSSO: true
    });

    await CSRFTokenSecret.findOneAndUpdate({ _id: savedCSRFTokenSecret._id }, { user_id: savedUser._id });
    await Profile.findOneAndUpdate({ _id: savedProfile._id }, { user_id: savedUser._id });

    const authenticationToken = jwt.sign({ _id: savedUser._id }, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, { expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING });

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });
    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, {
        httpOnly: true, secure: true, sameSite: 'none', path: '/',
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    return res.status(200).json({ status: 'ok' });
});

export default {
    user,
    deleteUser,
    register,
    activate,
    login,
    logout,
    forgotPassword,
    resetPassword,
    accountRecoveryResetPasswordVerifyToken,
    ssoSignInGoogleIdentityServices,
    ssoSignUpGoogleIdentityServices,
};
