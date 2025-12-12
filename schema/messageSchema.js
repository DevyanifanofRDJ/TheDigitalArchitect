import mongoose from 'mongoose';

const messageSchema=mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    typedEmail:{
        type:String,
        required:true,
    },
    actualEmail:{
        type:String,
        required:true
    },
    message:{
        type:String,
        required:true,
    }
});

export default messageSchema;