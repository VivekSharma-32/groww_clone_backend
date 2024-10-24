const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { StatusCodes } = require("http-status-codes");
const {
  BadRequestError,
  UnauthenticatedError,
  NotFoundError,
} = require("../../errors");
const User = require("../../models/User");

const register = async (req, res) => {
  const { email, password, register_token } = req.body;
  if (!email || !password || !register_token) {
    throw new BadRequestError("Invalid Request");
  }

  const user = await User.findOne({ email });
  if (user) {
    throw new BadRequestError("User already exist!");
  }

  try {
    const payload = jwt.verify(register_token, process.env.REGISTER_SECRET);
    if (payload.email !== email) {
      throw new BadRequestError("Invalid Token or expired");
    }

    const new_user = await User.create({ email: email, password: password });
    const access_token = new_user.createAccessToken();
    const refresh_token = new_user.createRefreshToken();
    res.status(StatusCodes.CREATED).json({
      user: { userId: new_user.id, email: new_user.email },
      tokens: { access_token: access_token, refresh_token: refresh_token },
    });
  } catch (error) {
    throw new BadRequestError("Invalid body");
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      throw new BadRequestError("Please provide email and password");
    }
    const user = await User.findOne({ email });

    if (!user) {
      throw new UnauthenticatedError("Invalid Credentials !!!");
    }

    const isPasswordCorrect = await user.comparePassword(password);
    if (!isPasswordCorrect) {
      let message;
      if (
        user.blocked_until_password &&
        user.blocked_until_password > new Date()
      ) {
        const remainingMinutes = Math.ceil(
          (user.blocked_until_password - new Date()) / (60 * 100)
        );
        message = `Your account is blocked for password. Please try again after ${remainingMinutes}`;
      } else {
        const attemptsRemaining = 3 - user.wrong_password_attempts;
        message =
          attemptsRemaining > 0
            ? `Invalid password, ${attemptsRemaining} attempt(s) remaining`
            : "Invalid login attempts. Please try after 30 minutes.";
      }
      throw new UnauthenticatedError(message);
    }

    const access_token = user.createAccessToken();
    const refresh_token = user.createRefreshToken();
    const phone_exist = false;
    const login_pin_exist = false;

    if (user.phone_exist) {
      phone_exist = true;
    }

    if (user.login_pin_exist) {
      login_pin_exist = true;
    }

    res.status(StatusCodes.OK).json({
      user: {
        userId: user.id,
        name: user.name,
        phone_exist,
        login_pin_exist,
      },
      tokens: {
        access_token: access_token,
        refresh_token: refresh_token,
      },
    });
  } catch (error) {
    console.log(error);
  }
};

const refreshToken = async (req, res) => {
  const { type, refresh_token } = req.body;
  if (!type || !["socket", "app"].includes(type) || !refresh_token) {
    throw new BadRequestError("Invalid body");
  }
  try {
    let accessToken, newRefreshToken;
    if (type === "socket") {
      ({ accessToken, newRefreshToken } = await generateRefreshTokens(
        refresh_token,
        process.env.REFRESH_SOCKET_TOKEN_SECRET,
        process.env.REFRESH_SOCKET_TOKEN_EXPIRY,
        process.env.SOCKET_TOKEN_SECRET,
        process.env.SOCKET_TOKEN_EXPIRY
      ));
    } else if (type === "app") {
      ({ accessToken, newRefreshToken } = await generateRefreshTokens(
        refresh_token,
        process.env.REFRESH_TOKEN_SECRET,
        process.env.REFRESH_SOCKET_TOKEN_EXPIRY,
        process.env.JWT_SECRET,
        process.env.ACCESS_TOKEN_EXPIRY
      ));
    }

    res
      .status(StatusCodes.OK)
      .json({ access_token: accessToken, refresh_token: newRefreshToken });
  } catch (error) {
    console.error(error);
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: "Invalid or expired token" });
  }
};

async function generateRefreshTokens(
  token,
  refresh_secret,
  refresh_expiry,
  access_secret,
  access_expiry
) {
  try {
    const payload = jwt.verify(token, refresh_secret);
    const user = await User.findById(payload.userId);
    if (!user) {
      throw new NotFoundError("User not found");
    }

    const accessToken = await jwt.sign({ userId: user.id }, access_secret, {
      expiresIn: access_expiry,
    });

    const newRefreshToken = await jwt.sign(
      { userId: user.id },
      refresh_secret,
      {
        expiresIn: refresh_expiry,
      }
    );

    return { accessToken, newRefreshToken };
  } catch (error) {
    console.error(error);
    throw new UnauthenticatedError("Invalid or expired token");
  }
}

module.exports = { register, login, refreshToken };
