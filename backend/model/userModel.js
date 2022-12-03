const mongoose = require('mongoose')

const userSchema = mongoose.Schema
({
    name: {
        type: String,
        required: [true, 'Please add a name']
    },
    email: {
        type: String,
        required: [true, 'Please add an email'],
        unique: true
    },
    password: {
        type: String,
        required: [true, 'Please add a string password']
    },
    contactNumber: {
        type: Number,
        required: [true, 'Please add your number']
    },
},
{
    timestamps: true
})


module.exports = mongoose.model('User', userSchema)