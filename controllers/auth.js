const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("../models/userSchema");
const HttpError = require("../helpers/error");
const { SECRET_KEY } = require("../config");

const register = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user) {
    return HttpError(res, 409, "Email in use");
  } else {
    const hashPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ ...req.body, password: hashPassword });
    res.status(201).json({
      user: { email: newUser.email, subscription: "starter" },
    });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!passwordCompare || !user.email) {
    return HttpError(res, 401, "Email or password is wrong");
  }

  const payload = {
    id: user._id,
  };

  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "12h" });
  await User.findByIdAndUpdate(user._id, { token });

  res.json({
    token: token,
    user: {
      email: user.email,
      subscription: user.subscription,
    },
  });
};

const logout = async (req, res) => {
  const { _id } = req.user;
  if (!req.user) {
    return HttpError(res, 401, "Not authorized");
  }
  await User.findByIdAndUpdate(_id, { token: "" });

  res.status(204).json();
};

const getCurrent = async (req, res) => {
  if (!req.user) {
    return HttpError(res, 401, "Not authorized");
  }
  const { email, subscription } = req.user;
  res.json({
    email,
    subscription,
  });
};

const setSubscription = async (req, res) => {
  const { _id } = req.user;
  const result = await User.findByIdAndUpdate(_id, req.body, {
    new: true,
  });

  if (!result) {
    return HttpError(res, 404, "Not found");
  }
  res.status(200).json(result);
};

module.exports = {
  register,
  login,
  logout,
  getCurrent,
  setSubscription,
};
