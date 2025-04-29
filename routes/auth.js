import express from 'express';
import { refreshToken, auth, login, register, testAuth, getUserProfile, updateUserProfile } from '../controllers/auth.js';
import authenticateUser from '../middleware/authentication.js';

const router = express.Router();

router.get('/', testAuth);
router.post('/refresh-token', refreshToken);
router.post('/signin', auth); // Legacy endpoint
router.post('/login', login); // New email/password login
router.post('/register', register); // New registration endpoint
router.get('/profile', authenticateUser, getUserProfile); // Get user profile
router.put('/profile', authenticateUser, updateUserProfile); // Update user profile

export default router;
