import express from 'express';
import v1AuthenticationController from '../controllers/v1AuthenticationController.js';
import * as middlewareLimiter from '../middlewares/v1AuthenticationLimiter.js';
import * as middleware from '../middlewares/index.js';

const router = express.Router();

// PUBLIC ROUTES
router.post('/register', middlewareLimiter.registerLimiter, middleware.verifyPublicCSRFToken, v1AuthenticationController.register);
router.post('/login', middlewareLimiter.loginLimiter, middleware.verifyPublicCSRFToken, v1AuthenticationController.login);
router.post('/activate', middlewareLimiter.activateLimiter, middleware.verifyPublicCSRFToken, v1AuthenticationController.activate);
router.post('/forgot-password', middlewareLimiter.forgotPasswordLimiter, middleware.verifyPublicCSRFToken, v1AuthenticationController.forgotPassword);

// SSO
router.post('/sso/sign-in/google-identity-services', middlewareLimiter.loginLimiter, middleware.verifyPublicCSRFToken, v1AuthenticationController.ssoSignInGoogleIdentityServices);
router.post('/sso/sign-up/google-identity-services', middlewareLimiter.loginLimiter, middleware.verifyPublicCSRFToken, v1AuthenticationController.ssoSignUpGoogleIdentityServices);

// PROTECTED ROUTES
router.get('/user', middlewareLimiter.userLimiter, middleware.sendPublicCSRFTokenToUser, middleware.isAuthenticated, v1AuthenticationController.user);
router.delete('/user', middlewareLimiter.deleteUserLimiter, middleware.sendPublicCSRFTokenToUser, middleware.isAuthenticated, v1AuthenticationController.deleteUser);
router.post('/logout', middlewareLimiter.logoutLimiter, middleware.sendPublicCSRFTokenToUser, middleware.isAuthenticated, v1AuthenticationController.logout);

// RESET PASSWORD (verifies CSRF inside controller)
router.post('/reset-password', middlewareLimiter.resetPasswordLimiter, v1AuthenticationController.resetPassword);
router.post('/account-recovery/reset-password/verify-token', middlewareLimiter.resetPasswordVerifyTokenLimiter, v1AuthenticationController.accountRecoveryResetPasswordVerifyToken);

export default router;
