const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { UnauthenticatedError } = require("../errors");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      maxlength: 50,
      minlength: 3,
    },
    email: {
      type: String,
      required: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        "Please provide a valid email",
      ],
      unique: true,
    },
    password: {
      type: String,
    },
    login_pin: {
      type: String,
      sparse: true, // To allow for null/undefined values in sparse index fields
    },
    phone_number: {
      type: String,
      match: [
        /^[0-9]{10}$/,
        "Please provide a 10-digit phone number without spaces or special characters",
      ],
      unique: true,
      sparse: true, // Ensure unique index allows null values
    },
    date_of_birth: {
      type: Date,
    },
    phone_verified: {
      type: Boolean,
      default: false,
    },
    biometricKey: {
      type: String,
    },
    gender: {
      type: String,
      enum: ["male", "female", "other"],
    },
    wrong_pin_attempts: {
      type: Number,
      default: 0,
    },
    blocked_until_pin: {
      type: Date,
      default: null,
    },
    wrong_password_attempts: {
      type: Number,
      default: 0,
    },
    blocked_until_password: {
      type: Date,
      default: null,
    },
    balance: {
      type: Number,
      default: 50000.0,
    },
  },
  { timestamps: true }
);

// Pre-save hook to hash password only if it's new or modified
userSchema.pre("save", async function () {
  if (this.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
});

userSchema.pre("save", async function () {
  if (this.isModified("login_pin")) {
    const salt = await bcrypt.genSalt(10);
    this.login_pin = await bcrypt.hash(this.login_pin, salt);
  }
});

userSchema.statics.updatePIN = async function (email, newPin) {
  try {
    const user = await this.findOne({ email });
    if (!user) {
      throw new NotFoundError("User not found");
    }

    const isSamePIN = await bcrypt.compare(newPin, user.login_pin);
    if (isSamePIN) {
      throw new BadRequestError(
        "New PIN must be different from the current PIN"
      );
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPIN = await bcrypt.hash(newPin, salt);

    await this.findOneAndUpdate(
      { email },
      { login_pin: hashedPIN, blocked_until_pin: null, wrong_pin_attempts: 0 }
    );

    return { success: true, message: "PIN updated successfully" };
  } catch (error) {
    throw error;
  }
};

userSchema.statics.updatePassword = async function (email, newPassword) {
  try {
    const user = await this.findOne({ email });
    if (!user) {
      throw new NotFoundError("User not found");
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      throw new BadRequestError(
        "New password must be different from the current password"
      );
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await this.findOneAndUpdate(
      { email },
      {
        password: hashedPassword,
        blocked_until_password: null,
        wrong_password_attempts: 0,
      }
    );

    return { success: true, message: "Password updated successfully" };
  } catch (error) {
    throw error;
  }
};

// Method to create a JSON Web Token
userSchema.methods.createJWT = function () {
  return jwt.sign(
    {
      userId: this._id,
      name: this.name,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_LIFETIME,
    }
  );
};

userSchema.methods.createAccessToken = function () {
  return jwt.sign(
    { userId: this._id, name: this.name },
    process.env.JWT_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
};

userSchema.methods.createRefreshToken = function () {
  return jwt.sign({ userId: this._id }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
  });
};

// Method to compare candidate password with hashed password
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (this.blocked_until_password && this.blocked_until_password > new Date()) {
    throw new UnauthenticatedError(
      "Invalid Login attempts exceeded. Please try after 30 minutes."
    );
  }

  const isMatch = await bcrypt.compare(candidatePassword, this.password);
  if (!isMatch) {
    this.wrong_password_attempts += 1;
    if (this.wrong_password_attempts >= 3) {
      const blockDuration = 30 * 60 * 1000;
      this.blocked_until_password = new Date(Date.now() + blockDuration);
      this.wrong_password_attempts = 0;
    }

    await this.save();
  } else {
    this.wrong_password_attempts = 0;
    this.blocked_until_password = null;
    await this.save();
  }

  return isMatch;
};

userSchema.methods.comparePIN = async function comparePIN(candidatePIN) {
  if (this.blocked_until_pin && this.blocked_until_pin > new Date()) {
    throw new UnauthenticatedError("Limit Exceeded,try after 30 minutes.");
  }

  const hashedPIN = this.login_pin;

  const isMatch = await bcrypt.compare(candidatePIN, hashedPIN);

  if (!isMatch) {
    this.wrong_pin_attempts += 1;
    if (this.wrong_pin_attempts > 3) {
      const blockDuration = 30 * 60 * 1000;
      this.blocked_until_pin = new Date(Date.now() + blockDuration);
      this.wrong_pin_attempts = 0;
    }
    await this.save();
  } else {
    this.wrong_pin_attempts = 0;
    this.blocked_until_pin = null;
    await this.save();
  }

  return isMatch;
};

const User = mongoose.model("User", userSchema);

module.exports = User;
