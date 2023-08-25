import express from 'express';
import authController from '../controllers/authController';

const router = express.Router();

router.post(
  '/signup',
  authController.uploadUserPhoto,
  authController.resizeUserPhoto,
  authController.signup,
  authController.sendOTP
);
router.post('/sendOTP', authController.sendOTP);
router.post('/verify-email', authController.verifyEmail);
router.post('/login', authController.login);

export default router;
