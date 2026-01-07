import { User } from "../models/user.models.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { ApiError } from "../utils/apiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
} from "../utils/mail.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";

const generateAcessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = await user.generateAccessToken();
    const refreshToken = await user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    console.log(error);
    throw new ApiError(500, "Something went wrong while generating tokens");
  }
};

const registerUser = asyncHandler(async (req, res) => {
  if (!req?.body) throw new ApiError(401, "All fields are required");

  const { email, username, password, role } = req.body;

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with username or email already exsist");
  }

  const user = await User.create({
    email,
    password,
    username,
    isEmailVerified: false,
  });

  const { unhashed, hashed, tokenExpiry } = await user.generateTemporaryToken();
  user.emailVerificationToken = hashed;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });
  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unhashed}`
    ),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshtoken -emailVerificationToken -emailVerificationExpiry"
  );

  if (!createdUser)
    throw new ApiError(501, "Something went wrong while registering the user");

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user: createdUser },
        "User registered successfully and verification email has been sent"
      )
    );
});

//TODO: ADD OTP FOR 2 STEP VERIFICATION
const loginUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;

  if (!username && !email) {
    throw new ApiError(400, "Username or email is required");
  }

  const user = await User.findOne({
    $or: [{ email }, { username }],
  });

  console.log(user);
  if (!user) {
    throw new ApiError(404, "User with this email or username does not exist");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(409, "Password is incorrect");
  }

  const loggedInUser = await User.findById(user.id).select(
    "-password -refreshtoken -emailVerificationToken -emailVerificationExpiry"
  );

  if (!loggedInUser) {
    throw new ApiError(500, "Something went wrong with our servers.");
  }

  const { accessToken, refreshToken } = await generateAcessAndRefreshToken(
    user._id
  );

  const options = {
    httpOnly: true,
    secure: true,
    path: "/",
    sameSite: "strict",
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "User logged in successfully"
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  const user = req?.user;
  if (!user) {
    throw new ApiError(404, "User is not logged in or not found");
  }

  const updatedUser = await User.findByIdAndUpdate(user._id, {
    refreshToken: "",
  });

  if (!updatedUser) {
    throw new ApiError(500, "User could not be logged out");
  }

  const options = {
    httpOnly: true,
    secure: true,
    path: "/",
    sameSite: "strict",
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  if (!req?.user) {
    throw new ApiError(404, "User not found.Please login!");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "User retrieved successfully"));
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    throw new ApiError(401, "Both old and new passwords are required");
  }
  let user;
  try {
    user = await User.findById(req?.user._id);
  } catch (err) {
    throw new ApiError(500, "Unable to fetch the user.", [err]);
  }

  if (!user) {
    throw new ApiError(409, "Invalid user, please login again");
  }

  const isPasswordValid = await user.isPasswordCorrect(oldPassword);
  if (!isPasswordValid) {
    throw new ApiError(
      409,
      "Password is incorrect. Please try again or try resetting your password."
    );
  }

  user.password = newPassword;
  const updatedUser = await user.save({ validateBeforeSave: false });

  if (!updatedUser) {
    throw new ApiError(500, "Unable to update user password please try again.");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password updated successfully."));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    throw new ApiError(402, "Refresh token is required.");
  }

  const decodedToken = await jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET
  );

  if (!decodedToken) {
    throw new ApiError(409, "Your tokens has expired please login again");
  }

  const user = await User.findById(decodedToken._id);
  if (!user) {
    throw new ApiError(500, "Unable to create user please try again");
  }

  if (user.refreshToken !== refreshToken) {
    throw new ApiError(409, "Refresh token is expired. Please login again");
  }

  const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
    await generateAcessAndRefreshToken(user._id);

  user.refreshToken = newRefreshToken;
  const updatedUser = await user.save({ validateBeforeSave: false });

  if (!updatedUser) {
    throw new ApiError(500, "Unable to update and generate new tokens");
  }

  const options = {
    httpOnly: true,
    secure: true,
    path: "/",
    sameSite: "strict",
  };

  return res
    .status(200)
    .cookie("accessToken", newAccessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
      new ApiResponse(
        200,
        { accessToken: newAccessToken, refreshToken: newRefreshToken },
        "Tokens refreshed successfully"
      )
    );
});

const sendforgotPasswordEmail = asyncHandler(async (req, res) => {
  const { email, username } = req.body;
  if (!email && !username) {
    throw new ApiError(409, "Either username or email is required");
  }
  const user = await User.findOne({ $or: [{ username }, { email }] });

  if (!user) {
    throw new ApiError(
      404,
      "Unable to find user with the given username or email"
    );
  }

  const { unhashed, hashed, tokenExpiry } = await user.generateTemporaryToken();
  user.forgotPasswordToken = hashed;
  user.forgotPasswordExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: "Password reset email",
    mailgenContent: forgotPasswordMailgenContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/reset-password/${unhashed}`
    ),
  });

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "Reset password mail sent successfully to your registred email id."
      )
    );
});

const verifyUserEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;
  if (!verificationToken) {
    throw new ApiError(404, "No verification token found.");
  }

  const hashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() },
  });
  if (!user) {
    throw new ApiError(404, "No such user found please try again");
  }

  user.isEmailVerified = true;
  user.emailVerificationToken = "";
  user.emailVerificationExpiry = null;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Email verified successfully"));
});

const resetForgottenPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;
  if (!resetToken) {
    throw new ApiError(404, "No password reset token found.");
  }

  if (!newPassword) {
    throw new ApiError(401, "Password is required for updation.");
  }

  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });
  if (!user) {
    throw new ApiError(404, "Invalid or expired token please try again.");
  }

  user.password = newPassword;
  user.forgotPasswordToken = "";
  user.forgotPasswordExpiry = null;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password reset successfully"));
});

const resendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req?.user?._id);

  if (!user) {
    throw new ApiError(409, "Please login first to verify the email");
  }

  const { unhashed, hashed, tokenExpiry } = await user.generateTemporaryToken();
  user.emailVerificationToken = hashed;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });
  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unhashed}`
    ),
  });
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "Email verification mail sent to the registered email successfully"
      )
    );
});

export {
  registerUser,
  loginUser,
  logoutUser,
  getCurrentUser,
  changeCurrentPassword,
  refreshAccessToken,
  sendforgotPasswordEmail,
  verifyUserEmail,
  resetForgottenPassword,
  resendVerificationEmail,
};
