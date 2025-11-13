from flask_mail import Mail, Message
from flask import render_template_string
import os

mail = Mail()

def init_mail(app):
    """Initialize Flask-Mail with app"""
    mail.init_app(app)
    return mail

def send_verification_email(user_email, user_name, token, site_url):
    """Send email verification link"""
    try:
        verification_link = f"{site_url}/verify-email/{token}"
        
        subject = "Verify Your Email - MFQOD Platform"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f9f9f9;
                }}
                .header {{
                    background-color: #4F46E5;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    background-color: white;
                    padding: 30px;
                    border-radius: 0 0 5px 5px;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background-color: #4F46E5;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 20px;
                    color: #666;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to MFQOD Platform!</h1>
                </div>
                <div class="content">
                    <h2>Hi {user_name},</h2>
                    <p>Thank you for registering with MFQOD Platform. Please verify your email address to activate your account.</p>
                    <p>Click the button below to verify your email:</p>
                    <center>
                        <a href="{verification_link}" class="button">Verify Email Address</a>
                    </center>
                    <p>Or copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #4F46E5;">{verification_link}</p>
                    <p><strong>This link will expire in 24 hours.</strong></p>
                    <p>If you didn't create an account, you can safely ignore this email.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 MFQOD Platform. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Hi {user_name},
        
        Thank you for registering with MFQOD Platform. Please verify your email address to activate your account.
        
        Click the link below to verify your email:
        {verification_link}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, you can safely ignore this email.
        
        Best regards,
        MFQOD Platform Team
        """
        
        msg = Message(subject, recipients=[user_email])
        msg.body = text_body
        msg.html = html_body
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending verification email: {e}")
        return False

def send_password_reset_email(user_email, user_name, token, site_url):
    """Send password reset email"""
    try:
        reset_link = f"{site_url}/reset-password/{token}"
        
        subject = "Reset Your Password - MFQOD Platform"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f9f9f9;
                }}
                .header {{
                    background-color: #DC2626;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    background-color: white;
                    padding: 30px;
                    border-radius: 0 0 5px 5px;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background-color: #DC2626;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 20px;
                    color: #666;
                    font-size: 12px;
                }}
                .warning {{
                    background-color: #FEF3C7;
                    border-left: 4px solid #F59E0B;
                    padding: 10px;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Password Reset Request</h1>
                </div>
                <div class="content">
                    <h2>Hi {user_name},</h2>
                    <p>We received a request to reset your password for your MFQOD Platform account.</p>
                    <p>Click the button below to reset your password:</p>
                    <center>
                        <a href="{reset_link}" class="button">Reset Password</a>
                    </center>
                    <p>Or copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #DC2626;">{reset_link}</p>
                    <p><strong>This link will expire in 1 hour.</strong></p>
                    <div class="warning">
                        <strong>⚠️ Security Notice:</strong>
                        <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
                    </div>
                </div>
                <div class="footer">
                    <p>&copy; 2025 MFQOD Platform. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Hi {user_name},
        
        We received a request to reset your password for your MFQOD Platform account.
        
        Click the link below to reset your password:
        {reset_link}
        
        This link will expire in 1 hour.
        
        If you didn't request a password reset, please ignore this email or contact support if you have concerns.
        
        Best regards,
        MFQOD Platform Team
        """
        
        msg = Message(subject, recipients=[user_email])
        msg.body = text_body
        msg.html = html_body
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending password reset email: {e}")
        return False

def send_welcome_email(user_email, user_name, site_url):
    """Send welcome email after successful verification"""
    try:
        subject = "Welcome to MFQOD Platform!"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f9f9f9;
                }}
                .header {{
                    background-color: #10B981;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    background-color: white;
                    padding: 30px;
                    border-radius: 0 0 5px 5px;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background-color: #10B981;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 20px;
                    color: #666;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Account Verified!</h1>
                </div>
                <div class="content">
                    <h2>Welcome, {user_name}!</h2>
                    <p>Your email has been successfully verified. You can now enjoy all features of MFQOD Platform:</p>
                    <ul>
                        <li>📝 Post lost and found items</li>
                        <li>💬 Connect with other users</li>
                        <li>🔔 Get real-time notifications</li>
                        <li>🔍 Search for items</li>
                    </ul>
                    <center>
                        <a href="{site_url}/home" class="button">Start Exploring</a>
                    </center>
                    <p>If you have any questions, feel free to contact our support team.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 MFQOD Platform. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Welcome, {user_name}!
        
        Your email has been successfully verified. You can now enjoy all features of MFQOD Platform.
        
        Visit: {site_url}/home
        
        If you have any questions, feel free to contact our support team.
        
        Best regards,
        MFQOD Platform Team
        """
        
        msg = Message(subject, recipients=[user_email])
        msg.body = text_body
        msg.html = html_body
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending welcome email: {e}")
        return False
