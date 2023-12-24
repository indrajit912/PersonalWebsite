# Main routes of the Webapp
# Author: Indrajit Ghosh
# Created On: Dec 22, 2023
#

from . import main_bp

from flask import render_template, redirect, url_for, request


#######################################################
#                      Homepage
#######################################################
@main_bp.route('/')
def index():
    return render_template('index.html')


@main_bp.route('/research/')
def research():
    return render_template('research.html')