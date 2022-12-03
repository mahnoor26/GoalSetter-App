const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../model/userModel')


// @desc    register new user
// @route   POST /api/users
// @access  Public
const registerUser = asyncHandler(async (req,res) =>
{
    const{name, email, password, contactNumber} = req.body

    if(!name || !email || !password || !contactNumber)
    {
        res.status(400)
        throw new Error('Please add all fields')
    }

    //check if user exists 
    const userExists = await User.findOne({email})
    if(userExists){
        res.status(400)
        throw new Error('User already exits')
    }

    // Hash password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    // Create User 
    const user = await User.create({
        name, 
        email, 
        password: hashedPassword, 
        contactNumber
    })

    if(user)
    {
        res.status(201).json
        ({
            id: user.id,
            name: user.name,
            email: user.email,
            contactNumber: user.contactNumber,
            token: generateToken(user.id)
        })
    }
    else
    {
        res.status(400)
        throw new Error('Invalid user data')
    }

})

// @desc    Authenticate new user
// @route   POST /api/users/login
// @access  Public
const loginUser = asyncHandler(async (req,res) =>
{
    const { email, password} = req.body
    const user = await User.findOne({email})

    if( user && (await bcrypt.compare(password, user.password)))
    {
        res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            contactNumber: user.contactNumber,
            token: generateToken(user.id)
        })
    }
    else{
        res.status(400)
        throw new Error('Invalid Credentials')
    }

})

// @desc    Get user data
// @route   GET /api/goals/me
// @access  Private
const getMe = asyncHandler(async (req,res) =>
{
    res.status(200).json(req.user)
})

// Generate JWT Token

const generateToken = (id) =>
{
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: '30d',
    })
}

module.exports = {
    registerUser,
    loginUser,
    getMe
}