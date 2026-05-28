import dotenv from 'dotenv';
dotenv.config();
import rateLimit from 'express-rate-limit';
// @ts-ignore
import MongoStore from 'rate-limit-mongo';

const mongoStore = (collectionName: string) => new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string,
    collectionName,
    expireTimeMs: 60 * 1000,
    errorHandler: console.error,
});

export const userLimiter = rateLimit({ store: mongoStore('user-limits'), max: 100, message: 'Too many user requests, Please try again later.' });
export const loginLimiter = rateLimit({ store: mongoStore('login-limits'), max: 100, message: 'Too many login requests, Please try again later.' });
export const registerLimiter = rateLimit({ store: mongoStore('register-limits'), max: 100, message: 'Too many register requests, Please try again later.' });
export const activateLimiter = rateLimit({ store: mongoStore('activate-limits'), max: 100, message: 'Too many activate requests, Please try again later.' });
export const forgotPasswordLimiter = rateLimit({ store: mongoStore('forgot-password-limits'), max: 100, message: 'Too many forgot password requests, Please try again later.' });
export const resetPasswordLimiter = rateLimit({ store: mongoStore('reset-password-limits'), max: 100, message: 'Too many reset password requests, Please try again later.' });
export const resetPasswordVerifyTokenLimiter = rateLimit({ store: mongoStore('reset-password-verify-token-limits'), max: 100, message: 'Too many reset password verify token requests, Please try again later.' });
export const deleteUserLimiter = rateLimit({ store: mongoStore('delete-user-limits'), max: 100, message: 'Too many delete user requests, Please try again later.' });
export const logoutLimiter = rateLimit({ store: mongoStore('logout-limits'), max: 100, message: 'Too many logout requests, Please try again later.' });
export const refreshLimiter = rateLimit({ store: mongoStore('refresh-limits'), max: 100, message: 'Too many refresh requests, Please try again later.' });
