import mongoose from 'mongoose';
import userSchema from '../schema/userSchema.js';

const userModel=mongoose.model("userDetails",userSchema,"userDetails");

export default userModel;