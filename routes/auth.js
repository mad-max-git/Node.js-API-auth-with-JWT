const router = require("express").Router();
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { registerValidation, loginValidation } = require("../validation");

//REGISTER
router.post("/register", async (request, response) => {
  //LETS VALIDATE THE DATA BEFORE WE MAKE A USER
  const { error } = registerValidation(request.body);
  if (error) return response.status(400).send(error.details[0].message);

  //Checking if the user is already in the database
  const emailExist = await User.findOne({ email: request.body.email });
  if (emailExist) return response.status(400).send("Email already exists");

  //Hash passwords
  const salt = await bcrypt.genSalt();
  const hashedPassword = await bcrypt.hash(request.body.password, salt);

  //Create a new user
  const user = new User({
    name: request.body.name,
    email: request.body.email,
    password: hashedPassword
  });
  try {
    const savedUser = await user.save();
    response.send({ user: user._id });
  } catch (error) {
    response.status(400).send(error);
  }
});

//LOGIN
router.post("/login", async (request, response) => {
  //LETS VALIDATE THE DATA BEFORE WE MAKE A USER
  const { error } = loginValidation(request.body);
  if (error) return response.status(400).send(error.details[0].message);
  //Checking if the email exists
  const user = await User.findOne({ email: request.body.email });
  if (!user) return response.status(400).send("Email is not found");
  //PASSWORD IS CORRECT
  const validPass = await bcrypt.compare(request.body.password, user.password);
  if (!validPass) return response.status(400).send("Invalid password");

  const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET);
  response.header("auth-token", token).send(token);
});

module.exports = router;
