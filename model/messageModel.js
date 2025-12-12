import mongoose from 'mongoose';
import messageSchema from '../schema/messageSchema.js';

const messageModel=mongoose.model("userMessages",messageSchema,"userMessages");

export default messageModel;