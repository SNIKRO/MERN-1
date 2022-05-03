const { Router } = require('express')
const bycrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

router.post('/register', 

  [
    check('email', 'Bad email').isEmail(),
    check('password','Password too small').isLength({ min:6 })
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req)

    if(!errors.isEmpty()){
      return res.status(400).json({
        errors: errors.array(),
        message: 'Incorrect data'
      })
    }

    const {email , password} = req.body
    const candidate = await User.findOne({ email}) 
    
    if (candidate) {
      return res.status(400).json({message:'User already exist'})
    }

    const hashPassword = await bycrypt.hash(password, 12)

    const user = new User({ email, password: hashPassword })

    await user.save()

    res.status(201).json({ message:"User create" })
 
  } catch (error) {
    res.status(500).json({ message: "Something go wrong!!!!"})
  }
})

router.post('/login',
  [
    check('email', 'Enter correct email').normalizeEmail().isEmail(),
    check('password', 'Enter a password').exists()

  ],
  async (req, res) => {
  try {

    const errors = validationResult(req)

    if(!errors.isEmpty){
      return res.status(400).json({
        errors: errors.array(),
        message: 'Incorrect data on login'
      })
    }

    const {email, password} = req.body

    const user = await User.findOne({ email })

    if (!user){
      return res.status(400).json({message: 'User not found'})
    }

    const isMatch = await bycrypt.compare(password, user.password)

    if (!isMatch){
      return res.status(500).json({ message:'Wrong password' })
    }

    const token = jwt.sign(
      { userId: user.id },
      config.getw('jwtSecret'),
      { expiresIn: '1h' }
    )

    res.json({ token, userId: user.id})

  } catch (error) {
    res.status(500).json({ message: "Something go wrong"})
  }

})

module.exports = router