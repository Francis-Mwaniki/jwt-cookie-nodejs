const router = require("express").Router();
const User = require("../model/user");
const bcrypt = require("bcryptjs");
router.get("/", (req, res) => {
  res.json({
    message: "Welcome to my api",
  });
});

router.post("/register", async (req, res) => {
  const salt = await bcrypt.genSalt(10);

  console.log(req.body);
  /*   const hashedPassword = await bcrypt.hash(password, salt);
  const user = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  });
  await user.save();
  res.send(`${user.name} created successfully`); */
});
router.post("/login", (req, res) => {});

module.exports = router;
