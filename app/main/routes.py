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

from flask import render_template, redirect, url_for, request, jsonify, flash, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Email
from werkzeug.utils import secure_filename

from scripts.send_email_client import send_email_via_hermes
from scripts.utils import encrypt_with_public_key, encrypt_file_with_public_key, format_size
from config import APP_DATA_DIR, EmailConfig

#######################################################
#                      Homepage
#######################################################
@main_bp.route('/')
def index():
    indra_cv_link = "https://isibang-my.sharepoint.com/:b:/g/personal/rs_math1902_isibang_ac_in/IQDkz-GFFIrsSr_FKSNkBhHVASufnDTj2-6-Vfjq5gCkk8s?e=yrNGta"
    return render_template('index.html', indra_cv_link=indra_cv_link)


#######################################################
#                      Research
#######################################################
@main_bp.route('/research/')
def research():
    # These three things need to be calculated if the thesis gets modified.
    isi_thesis_link = "https://dspace.isical.ac.in/jspui/handle/10263/7620"
    thesis_link = "https://isibang-my.sharepoint.com/:b:/g/personal/rs_math1902_isibang_ac_in/EXHbeNS8ji5HuU0QhfWVNP0BZUG62aMsxPrDgp0ZBb9G0w?e=jpkLHE"
    thesis_sig_link = "https://isibang-my.sharepoint.com/:u:/g/personal/rs_math1902_isibang_ac_in/EeiKVBiZA05BlL-aFibEp5wBhE0XWN4m-kmjqMsjPPiW4w?e=o3WF5z"
    thesis_sha256sum = "7efd68b7ba90c61f640b05886bbd12a8162c92ce4223d8bcdbcbe215185db664"

    return render_template(
        'research.html',
        thesis_link=thesis_link,
        thesis_sig_link=thesis_sig_link,
        thesis_sha256sum=thesis_sha256sum,
        isi_thesis_link=isi_thesis_link
    )

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
            save_path = os.path.join(temp_dir, filename)

            # Avoid overwriting existing files
            counter = 1
            base, ext = os.path.splitext(save_path)
            while os.path.exists(save_path):
                save_path = f"{base}_{counter}{ext}"
                counter += 1

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
        encrypted_dir = APP_DATA_DIR / 'encrypted_attachments'
        encrypted_dir.mkdir(parents=True, exist_ok=True)

        # Encrypt attachments and collect output paths
        encrypted_attachment_paths = []
        attachment_filenames = []

        for raw_path in attachment_paths:
            real_filename = Path(raw_path).name
            encrypted_path = encrypt_file_with_public_key(public_key_path, raw_path, encrypted_dir)
            encrypted_attachment_paths.append(encrypted_path)
            attachment_filenames.append(real_filename)

        # Pair each filename with its corresponding encrypted path basename
        attachments = list(zip(
            attachment_filenames,
            [os.path.basename(p) for p in encrypted_attachment_paths],
            [format_size(os.path.getsize(p)) for p in encrypted_attachment_paths]
        ))

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
        # Encrypt the message
        encrypted_output = encrypt_with_public_key(public_key_path, combined)

        # Save encrypted JSON message
        message_filename = f"message_{uuid.uuid4().hex[:8]}.json"
        message_path = encrypted_dir / message_filename
        with open(message_path, 'w') as f:
            f.write(encrypted_output)

        return render_template(
            'preview_encrypted.html', 
            message_filename=message_filename,
            original_message_name='message.json',
            encrypted_attachment_paths=encrypted_attachment_paths,
            attachments=attachments
        )

    except Exception as e:
        print("Error in preview_whisper:", e)
        flash(f"Encryption failed: {str(e)}", "danger")
        return redirect(url_for('main.whisper'))


@main_bp.route('/send_encrypted/', methods=['POST'])
def send_encrypted():
    encrypted_dir = APP_DATA_DIR / 'encrypted_attachments'

    data = request.get_json()
    message_filename = data.get('message_filename')
    message_filepath = encrypted_dir / message_filename
    encrypted_attachments = data.get('encrypted_attachments', [])
    encrypted_attachments_paths = [message_filepath] + [Path(f) for f in encrypted_attachments]

    # Send email
    html_body = render_template("emails/whisper_email.html", message_filename=message_filename)

    # Use Hermes API to send email
    response = send_email_via_hermes(
        to=EmailConfig.INDRAJIT912_GMAIL,
        subject="You've got a whisper. It's encrypted. 🔐",
        email_html_text=html_body,
        attachments=[str(p) for p in encrypted_attachments_paths],
        api_key=EmailConfig.HERMES_API_KEY,
        bot_id=EmailConfig.HERMES_EMAILBOT_ID,
        api_url=EmailConfig.HERMES_BASE_URL + "/api/v1/send-email",
        from_name="Indrajit's Website Bot"
    )

    # Delete the attachments from the server
    for attachment_path in encrypted_attachments_paths:
        if attachment_path.exists():
            attachment_path.unlink()
            print(f"Attachment {attachment_path} deleted.")

    if response.get("success"):          
        return jsonify({"message": "Email sent successfully!", "redirect_url": url_for('main.thankyou')}), 200
    else:
        error = response.get('error', 'Unknown error occurred.')
        return jsonify({"message": error, "redirect_url": url_for('errors.email_send_error_route', error=error)}), 500
    

###########################################################
#               Download Attachments
###########################################################
@main_bp.route('/download_attachment/<path:filename>')
def download_attachment(filename):
    encrypted_dir = os.path.join(APP_DATA_DIR, 'encrypted_attachments')
    try:
        return send_from_directory(encrypted_dir, filename, as_attachment=True)
    except FileNotFoundError:
        flash("File not found.", "danger")
        return redirect(url_for('main.whisper'))


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

        api_url = EmailConfig.HERMES_BASE_URL + "/api/v1/send-email"
        response = send_email_via_hermes(
            to=EmailConfig.INDRAJIT912_GMAIL,
            subject="Message from your WebSite!",
            email_html_text=email_html_text,
            attachments=[str(p) for p in _attachment_paths],
            api_key=EmailConfig.HERMES_API_KEY,
            bot_id=EmailConfig.HERMES_EMAILBOT_ID,
            api_url=api_url,
            from_name="Indrajit's Website Bot"
        )

        # Delete the attachments from the server
        for attachment_path in _attachment_paths:
            if attachment_path.exists():
                attachment_path.unlink()

        if response.get("success"):          
            return redirect(url_for('main.thankyou'))
        else:
            error = response.get('error', 'Unknown error occurred.')
            return redirect(url_for('errors.email_send_error_route', error=error))

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
