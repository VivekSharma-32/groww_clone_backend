const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { StatusCodes } = require("http-status-codes");
const {
  BadRequestError,
  UnauthenticatedError,
  NotFoundError,
} = require("../../errors");
const User = require("../../models/User");
const { OAuth2Client } = require("google-auth-library");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const signInWithOauth = async (req, res) => {
  const { provider, id_token } = req.body;

  if (!provider || provider != "google" || provider != "apple") {
    throw new BadRequestError("Invalid Request");
  }

  try {
    if (provider == "apple") {
      // verify token
    }

    if (provider == "google") {
      // verify token
      const ticket = await googleClient.verifyIdToken({
        idToken: id_token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });

      ({ email } = ticket.getPayload());

      const user = await User.findOneAndUpdate(
        { email: email },
        { email_verified: true },
        { upsert: true, new: true }
      );

      const accessToken = user.createAccessToken();
      const refreshToken = user.createRefreshToken();
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
          name: user.name,
          userId: user.id,
          phone_exist,
          login_pin_exist,
        },
        tokens: { access_token: accessToken, refresh_token: refreshToken },
      });
    }
  } catch (error) {
    console.log(error);
    throw new UnauthenticatedError("Invalid token or expired");
  }
};

module.exports = { signInWithOauth };
