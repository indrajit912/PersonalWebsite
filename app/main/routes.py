# Main routes of the Webapp
# Author: Indrajit Ghosh
# Created On: Dec 22, 2023
#

from . import main_bp

from flask import render_template, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField
from wtforms.validators import DataRequired, Email, ValidationError

from pathlib import Path
from smtplib import SMTPAuthenticationError, SMTPException

from scripts.email_message import EmailMessage
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
#                       Contact Me!
######################################################################
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])


@main_bp.route('/contact/', methods=['GET', 'POST'])
def contact():
    form = ContactForm()

    if request.method == 'POST' and form.validate_on_submit():
        # Process the form data and send an email or save the message, etc.
        # Access form data using form.data
        name = form.name.data
        email_id = form.email.data
        subject = form.subject.data
        message_parts = form.message.data.split('\n')

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
        _email_html_text = render_template(
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
            email_html_text=_email_html_text,
            attachments=_attachment_paths
        )


        try:
            # Send the email to Indrajit
            msg.send(
                sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD, 
                server_info=EmailConfig.GMAIL_SERVER,
                print_success_status=False
            )

            # Delete the attachments from server
            for attachment_path in _attachment_paths:
                if attachment_path.exists():
                    attachment_path.unlink()


            # After processing, you can redirect to a thank-you page.
            return render_template('thank_you.html')
        
        except SMTPAuthenticationError as e:
            # TODO: Print the error `e` as 'Know More' button!
            # Redirect to the email authentication error page using the error blueprint
            return redirect(url_for('errors.email_auth_error_route'))
        
        
        except SMTPException as e:
            return redirect(url_for('errors.email_send_error_route'))
        
        except:
            # Handle email sending error
            return redirect(url_for('errors.generic_error_route'))


    return render_template('contact.html', form=form)

###########################################################
#               Test route
###########################################################
@main_bp.route('/devtest/')
def devtest():
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    return f"User IP: {user_ip}"
