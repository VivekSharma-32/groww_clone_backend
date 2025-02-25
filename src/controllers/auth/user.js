const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { StatusCodes } = require("http-status-codes");
const {
  BadRequestError,
  UnauthenticatedError,
  NotFoundError,
} = require("../../errors");
const User = require("../../models/User");

const updateProfile = async (req, res) => {
  const { name, gender, date_of_birth } = req.body;

  const accessToken = req.headers.authorization?.split(" ")[1];

  const decodedToken = jwt.verify(accessToken, process.env.JWT_SECRET);
  const userId = decodedToken.userId;

  const updatedFields = {};

  if (name) updatedFields.name = name;
  if (gender) updatedFields.gender = gender;
  if (date_of_birth) updatedFields.date_of_birth = date_of_birth;

  const updatedUser = await User.findByIdAndUpdate(userId, updatedFields, {
    new: true,
    runValidators: true,
    select: "-password",
  });

  if (!updatedUser) {
    throw new NotFoundError("User not found");
  }

  res.status(StatusCodes.OK).json({ success: true, data: updatedUser });
};

const setLoginPinFirst = async (req, res) => {
  const { login_pin } = req.body;

  if (!login_pin || login_pin.length != 4) {
    throw new BadRequestError("Bad Request Body");
  }

  const accessToken = req.headers.authorization?.split(" ")[1];

  const decodedToken = jwt.verify(accessToken, process.env.JWT_SECRET);
  const userId = decodedToken.userId;

  const user = await User.findById(userId);

  if (!user) {
    throw new BadRequestError("User not found");
  }

  if (user.login_pin) {
    throw new BadRequestError("Login PIN Exist! Use Reset PIN");
  }

  const updatedUser = await User.findByIdAndUpdate(
    userId,
    { login_pin },
    {
      new: true,
      runValidators: true,
    }
  );

  const access_token = await jwt.sign(
    { userId: userId },
    process.env.SOCKET_TOKEN_SECRET,
    {
      expiresIn: process.env.SOCKET_TOKEN_EXPIRY,
    }
  );

  const refresh_token = await jwt.sign(
    { userId: userId },
    process.env.REFRESH_SOCKET_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_SOCKET_TOKEN_EXPIRY,
    }
  );

  res.status(StatusCodes.OK).json({
    success: true,
    socket_tokens: {
      access_socket_token: access_token,
      refresh_socket_token: refresh_token,
    },
  });
};

const verifyPin = async (req, res) => {
  const { login_pin } = req.body;

  if (!login_pin || login_pin.length != 4) {
    throw new BadRequestError("Bad Request Body");
  }

  const accessToken = req.headers.authorization?.split(" ")[1];

  const decodedToken = jwt.verify(accessToken, process.env.JWT_SECRET);
  const userId = decodedToken.userId;

  const user = await User.findById(userId);

  if (!user || !user.login_pin) {
    throw new BadRequestError("Not found");
  }

  if (!user.login_pin) {
    throw new BadRequestError("Set your PIN first.");
  }

  const isVerifyingPin = await user.comparePIN(login_pin);

  if (!isVerifyingPin) {
    let message;
    if (user.blocked_until_pin && user.blocked_until_pin > new Date()) {
      const remainingMinutes = Math.ceil(
        (user.blocked_until_pin - new Date()) / (60 * 100)
      );
      message = `Your account is blocked for pin. Please try again after ${remainingMinutes}`;
    } else {
      const attemptsRemaining = 3 - user.wrong_password_attempts;
      message =
        attemptsRemaining > 0
          ? `Invalid pin, ${attemptsRemaining} attempt(s) remaining`
          : "Invalid login attempts. Please try after 30 minutes.";
    }
    throw new UnauthenticatedError(message);
  }

  const access_token = await jwt.sign(
    { userId: userId },
    process.env.SOCKET_TOKEN_SECRET,
    {
      expiresIn: process.env.SOCKET_TOKEN_EXPIRY,
    }
  );

  const refresh_token = await jwt.sign(
    { userId: userId },
    process.env.REFRESH_SOCKET_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_SOCKET_TOKEN_EXPIRY,
    }
  );

  res.status(StatusCodes.OK).json({
    success: true,
    socket_tokens: {
      access_socket_token: access_token,
      refresh_socket_token: refresh_token,
    },
  });
};

module.exports = {
  updateProfile,
  setLoginPinFirst,
  verifyPin,
};
