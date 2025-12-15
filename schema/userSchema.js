import mongoose from 'mongoose';

const userSchema=mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:false,
        select:false
    },
    googleId:{
        type:String,
        unique:true,
        sparse:true
    },
    role:{
        type:String,
        enum:['user','admin'],
        default:'user'
    }
});

export default userSchema;