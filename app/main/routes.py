# Main routes of the Webapp
# Author: Indrajit Ghosh
# Created On: Dec 22, 2023
#
import os
from pathlib import Path
import tempfile
import uuid
import json
from . import main_bp

from flask import render_template, redirect, url_for, request, jsonify, flash
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Email
from werkzeug.utils import secure_filename

from smtplib import SMTPAuthenticationError, SMTPException

from scripts.email_message import EmailMessage
from scripts.utils import encrypt_with_public_key, encrypt_file_with_public_key
from config import APP_DATA_DIR, EmailConfig

#######################################################
#                      Homepage
#######################################################
@main_bp.route('/')
def index():
    return render_template('index.html')


#######################################################
#                      Research
#######################################################
@main_bp.route('/research/')
def research():
    return render_template('research.html')

######################################################################
#                       CV
######################################################################
@main_bp.route('/cv/')
def cv():
    return render_template('cv.html')

######################################################################
#                       Photos
######################################################################
@main_bp.route('/photos/')
def photos():
    return render_template('photos.html')

######################################################################
#                       GPG Key
######################################################################
@main_bp.route('/gpgkey/')
def gpgkey():
    fingerprint = "13B8 DD7F 039E 9B8F 05ED  2175 4AAB EEA1 FB87 4A64"
    gpg_key_file = os.path.join(main_bp.static_folder, 'keys', 'indrajit_gpg_public_key.asc')
    with open(gpg_key_file, 'r') as f:
        gpg_key = f.read()
    return render_template('gpgkey.html', gpg_key=gpg_key, fingerprint=fingerprint)


######################################################################
#                       Whisper
######################################################################
@main_bp.route('/whisper/', methods=['GET', 'POST'])
def whisper():
    error = None

    if request.method == 'POST':
        user_name = request.form.get('name')
        user_email = request.form.get('email')
        user_message = request.form.get('message')
        browser_metadata_raw = request.form.get('browser_metadata')

        # Parse the JSON string into a Python dictionary
        try:
            browser_metadata = json.loads(browser_metadata_raw)
            user_ip = browser_metadata.get('ipAddress', 'Unavailable')
            user_platform = browser_metadata.get('platform', 'Unavailable')
            user_timestamp = browser_metadata.get('timestamp', 'Unavailable')
        except (json.JSONDecodeError, TypeError):
            browser_metadata = {}
            user_ip = user_platform = user_timestamp = 'Unavailable'

        # Manage attachments
        files = request.files.getlist('attachments')
        valid_files = [f for f in files if f and f.filename]

        temp_dir = tempfile.gettempdir()
        attachment_paths = []

        for file in valid_files:
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            save_path = os.path.join(temp_dir, unique_filename)
            file.save(save_path)
            attachment_paths.append(save_path)
        
        if not user_name or not user_email or not user_message:
            error = "All fields are required."
        else:
            return render_template('auto_post_to_preview.html', 
                               user_name=user_name,
                               user_email=user_email,
                               user_message=user_message,
                               user_ip=user_ip,
                               user_platform=user_platform,
                               user_timestamp=user_timestamp,
                               attachment_paths=attachment_paths)

    return render_template('whisper.html', error=error)

@main_bp.route('/preview_whisper/', methods=['POST'])
def preview_whisper():
    try:
        user_name = request.form.get('user_name')
        user_email = request.form.get('user_email')
        user_message = request.form.get('user_message')
        user_ip = request.form.get('user_ip')
        user_platform = request.form.get('user_platform')
        user_timestamp = request.form.get('user_timestamp')
        attachment_paths = request.form.getlist("attachment_paths")
        
        public_key_path = os.path.join(main_bp.static_folder, 'keys', 'indrajit_rsa_public_key.pem')

        # Handle attachments 
        encrypted_dir = os.path.join(APP_DATA_DIR, 'encrypted_attachments')
        os.makedirs(encrypted_dir, exist_ok=True)

        # Encrypt attachments and collect output paths
        encrypted_attachment_paths = []
        attachment_filenames = []

        for raw_path in attachment_paths:
            real_filename = raw_path.split("_", 1)[-1]
            encrypted_path = encrypt_file_with_public_key(public_key_path, raw_path, encrypted_dir)
            encrypted_attachment_paths.append(encrypted_path)
            attachment_filenames.append(real_filename)

        # Encrypt the message
        combined = f"""\
==============================
📨 New Message!
==============================

From          : {user_name} <{user_email}>
Sent At       : {user_timestamp}
Platform      : {user_platform}
IP            : {user_ip}
Attachment(s) : {len(attachment_filenames)}

------------------------------
📩 Message
------------------------------
{user_message}

==============================
📍 End of Message
==============================
"""
        encrypted_output = encrypt_with_public_key(public_key_path, combined)

        return render_template(
            'preview_encrypted.html', 
            encrypted_output=encrypted_output, 
            attachment_filenames=attachment_filenames,
            encrypted_attachment_paths=encrypted_attachment_paths
        )

    except Exception as e:
        print("Error in preview_whisper:", e)
        flash(f"Encryption failed: {str(e)}", "danger")
        return redirect(url_for('main.whisper'))


@main_bp.route('/send_encrypted/', methods=['POST'])
def send_encrypted():
    data = request.get_json()
    encrypted_output = data.get('encrypted_output')
    encrypted_attachments = data.get('encrypted_attachments', [])
    encrypted_attachments_paths = [Path(f) for f in encrypted_attachments]

    # Send email
    html_body = render_template("emails/whisper_email.html", encrypted_message=encrypted_output)

    # Create the email message
    msg = EmailMessage(
        sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
        to=EmailConfig.INDRAJIT912_GMAIL,
        subject="You've got a whisper. It's encrypted. 🔐",
        email_html_text=html_body,
        attachments=encrypted_attachments_paths
    )

    try:
        # Send the email to Indrajit
        msg.send(
            sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
            server_info=EmailConfig.GMAIL_SERVER,
            print_success_status=False
        )

        # Delete the attachments from the server
        for attachment_path in encrypted_attachments_paths:
            if attachment_path.exists():
                attachment_path.unlink()

        # Redirect to a thank-you page.
        return jsonify({"message": "Email sent successfully!", "redirect_url": url_for('main.thankyou')})

    except SMTPAuthenticationError as e:
        # TODO: Print the error `e` as 'Know More' button!
        # Redirect to the email authentication error page using the error blueprint
        return redirect(url_for('errors.email_auth_error_route'))

    except SMTPException as e:
        return redirect(url_for('errors.email_send_error_route'))
        
    except Exception as e:
        # Handle email sending error
        return redirect(url_for('errors.generic_error_route'))


######################################################################
#                       Contact Me!
######################################################################
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])


@main_bp.route('/contact/', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Process the form data and send an email or save the message, etc.
        name = request.form.get('name')
        email_id = request.form.get('email')
        subject = request.form.get('subject')
        message_parts = request.form.get('message').split('\n')

        # Process file attachments
        attachments = request.files.getlist('attachment[]')

        # Attach files to the email
        _attachment_paths = []
        for attachment in attachments:
            if attachment:
                _attachment_filename = APP_DATA_DIR / attachment.filename
                attachment.save(_attachment_filename)
                _attachment_paths.append(_attachment_filename)

        # Render the email template with the provided parameters
        email_html_text = render_template(
            'emails/email_template.html',
            name=name,
            subject=subject,
            message_parts=message_parts,
            email_id=email_id
        )

        # Create the email message
        msg = EmailMessage(
            sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
            to=EmailConfig.INDRAJIT912_GMAIL,
            subject="Message from your WebSite!",
            email_html_text=email_html_text,
            attachments=_attachment_paths
        )

        try:
            # Send the email to Indrajit
            msg.send(
                sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                server_info=EmailConfig.GMAIL_SERVER,
                print_success_status=False
            )

            # Delete the attachments from the server
            for attachment_path in _attachment_paths:
                if attachment_path.exists():
                    attachment_path.unlink()

            # After processing, you can redirect to a thank-you page.
            return redirect(url_for('main.thankyou'))

        except SMTPAuthenticationError as e:
            # TODO: Print the error `e` as 'Know More' button!
            # Redirect to the email authentication error page using the error blueprint
            return redirect(url_for('errors.email_auth_error_route'))

        except SMTPException as e:
            return redirect(url_for('errors.email_send_error_route'))

        except Exception as e:
            # Handle email sending error
            return redirect(url_for('errors.generic_error_route'))

    return render_template('contact.html')

###########################################################
#               Test route
###########################################################
@main_bp.route('/devtest/')
def devtest():
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    return f"User IP: {user_ip}"


@main_bp.route('/thankyou/')
def thankyou():
    return render_template('thank_you.html')