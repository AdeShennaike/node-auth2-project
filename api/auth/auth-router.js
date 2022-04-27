const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')
const magicToken = require('./auth-token-builder')

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
    try{
      const {username, password} = req.body
      const {role_name} = req
      const hash = bcrypt.hashSync(password, 8)
      const addUser = await User.add({ username, password: hash, role_name })
      res.json(addUser)
    }catch(err){
      next(err)
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
  try{
  const {username, password} = req.body
  const [user] = await User.findBy({username})
  const token = magicToken(user)
  if(username && bcrypt.compareSync(password, user.password)){
    res.json({message: `${username} is back!`, token})
  }else{
    next()
  }
  }catch(err){
    next(err)
  }
});

module.exports = router;
