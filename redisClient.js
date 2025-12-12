import 'dotenv/config';
import { createClient } from "redis";

const client=createClient({
    username:'default',
    password:process.env.REDIS_PASSWORD,
    socket:{
        host:process.env.REDIS_HOST,
        port:process.env.REDIS_PORT
    }
});

client.on('error',(err)=>console.log('Redis Error',err));
await client.connect();
console.log('Connected to Redis!');

export default client;