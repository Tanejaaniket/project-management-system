import { Router } from "express";
import {
  changeCurrentPassword,
  getCurrentUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
  resendVerificationEmail,
  resetForgottenPassword,
  sendforgotPasswordEmail,
  verifyUserEmail,
} from "../controllers/auth.controller.js";
import {
  changePasswordValidation,
  loginUserValidation,
  registerUserValidation,
  resetForgottenPasswordValidation,
  sendForgotPasswordEmailValidation,
} from "../validators/index.js";
import { validate } from "../middlewares/validator.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

//Unsecure routes
router.post("/register", registerUserValidation(), validate, registerUser);
router.post("/login", loginUserValidation(), validate, loginUser);
router.post("/refresh-token", refreshAccessToken);
router.get("/verify-email/:verificationToken", verifyUserEmail);
router.post(
  "/forgot-password",
  sendForgotPasswordEmailValidation(),
  validate,
  sendforgotPasswordEmail
);
router.post(
  "/reset-password/:resetToken",
  resetForgottenPasswordValidation(),
  validate,
  resetForgottenPassword
);

//Secure routes
router.post("/logout", verifyJWT, logoutUser);
router.get("/current-user", verifyJWT, getCurrentUser);
router.post(
  "/change-password",
  verifyJWT,
  changePasswordValidation(),
  validate,
  changeCurrentPassword
);
router.post("/resend-verification-email", verifyJWT, resendVerificationEmail);

export default router;
