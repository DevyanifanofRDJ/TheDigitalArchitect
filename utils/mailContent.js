const mailContent=(name,otp)=>{
    return `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
            <h2 style="color: #4f46e5;">Connection Request Received.</h2>
            <p>Hello <strong>${name}</strong>,</p>
            <p>We are establishing a secure link to your account. To complete the authentication handshake, please use the secure code below:</p>
            
            <div style="background-color: #f3f4f6; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0;">
                <h1 style="color: #1f2937; letter-spacing: 5px; font-family: 'Courier New', monospace; margin: 0;">${otp}</h1>
            </div>

            <p>This key is valid for the next <strong>600 seconds</strong>.</p>
            <p style="color: #6b7280; font-size: 0.9em; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 10px;">
                If you did not request this link, please disregard this message. Your secure node remains inactive.
                <br><br>
                — The Decent Engineer
            </p>
        </div>
    `;
};

export default mailContent;