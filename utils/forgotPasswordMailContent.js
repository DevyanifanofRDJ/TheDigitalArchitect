const forgotPasswordMailContent = (resetLink) => {
    return `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
            <h2 style="color: #4f46e5;">Access Recovery Mode Initiated.</h2>
            <p>Hello,</p>
            <p>We received a directive to overwrite the access credentials for your node. To define your new password, please verify via the secure link below:</p>
            
            <div style="background-color: #f3f4f6; padding: 25px; border-radius: 8px; text-align: center; margin: 20px 0;">
                <a href="${resetLink}" style="background-color: #4f46e5; color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 5px; font-weight: bold; font-size: 16px; display: inline-block;">INITIALIZE RESET</a>
            </div>

            <p>This link is valid for the next <strong>15 minutes</strong>.</p>
            <p style="color: #6b7280; font-size: 0.9em; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 10px;">
                If you did not request this protocol, please disregard this message. Your secure node remains active.
                <br><br>
                — The Decent Engineer
            </p>
        </div>
    `;
};

export default forgotPasswordMailContent;