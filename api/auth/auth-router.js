const router = require("express").Router();
const Users = require('../users/users-model');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const secrets = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    const credentials = req.body;

    try {
      const hash = bcrypt.hashSync(credentials.password);
      credentials.password = hash;

      const user = await Users.add(credentials);
      const token = generateToken(user);
      res.status(201).json({data: user, token});
    } catch (err) {
      next(err);
    }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

    const {username, password} = req.body;

    try {
      const [user] = await Users.findBy({username: username});

      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user);
        res.status(200).json({message: `${username} is back!`, token: token})
      } else {
        res.status(404).json({message: "Invalid login credentials"})
      }
    } catch (err) {
      next(err);
    }
});

const generateToken = (user) => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    rolename: user.role_name
  };

  const options = {
    expiresIn: "1d"
  };
  console.log(payload, "generateToken");

  const token = jwt.sign(payload, secrets.jwtSecret, options);

  return token;
}

module.exports = router;
