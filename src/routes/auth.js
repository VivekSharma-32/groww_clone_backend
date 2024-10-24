const express = require("express");
const { checkEmail } = require("../controllers/auth/email");
const {
  setPassword,
  login,
  refreshToken,
  register,
} = require("../controllers/auth/auth");
const { verifyOtp, sendOtp } = require("../controllers/auth/otp");
const authenticateUser = require("../middleware/authentication");
const {
  updateProfile,
  setLoginPinFirst,
  verifyPin,
} = require("../controllers/auth/user");
const { signInWithOauth } = require("../controllers/auth/oauth");
const {
  uploadBiometric,
  verifyBiometric,
} = require("../controllers/auth/biometrics");
const router = express.Router();

// router.post("/register", register);
router.post("/oauth", signInWithOauth);
router.post("/login", login);

router.post("/check-email", checkEmail);
router.post("/verify-otp", verifyOtp);
router.post("/send-otp", sendOtp);
router.post("/register", register);
router.put("/profile", authenticateUser, updateProfile);
router.put("/set-pin", authenticateUser, setLoginPinFirst);
router.put("/verify-pin", authenticateUser, verifyPin);
router.post("/upload-biometric", authenticateUser, uploadBiometric);
router.post("/verify-biometric", authenticateUser, verifyBiometric);
router.post("/refresh-token", refreshToken);

module.exports = router;
