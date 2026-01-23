# Routes for miscellanous bp
# Author: Indrajit Ghosh
# Created On: Dec 26, 2023
#

from . import misc_bp

from flask import render_template
from pathlib import Path

from scripts.utils import convert_zip_to_base64

#######################################################
#                      Routes
#######################################################
@misc_bp.route('/')
def index():
    _parent_dir = Path(__file__).parent.absolute()
    isi_phd_thesis_template_zip_path = _parent_dir / 'static' / 'others' / 'ISI_PhD_Thesis_Template.zip'
    isi_reg_zip_path = Path(__file__).parent.absolute() / 'static' / 'others' / 'isi_reg_form.zip'
    amsart_template_zip_path = Path(__file__).parent.absolute() / 'static' / 'others' / 'amsart_template_indrajit.zip'
    formal_letter_template_zip_path = Path(__file__).parent.absolute() / 'static' / 'others' / 'formal-letter-template-Indrajit.zip'
    beamer_template_zip_path = Path(__file__).parent.absolute() / 'static' / 'others' / 'beamer-template-indrajit.zip'

    return render_template(
        'misc.html', 
        convert_zip_to_base64=convert_zip_to_base64,
        isi_reg_zip_path=isi_reg_zip_path,
        amsart_template_zip_path=amsart_template_zip_path,
        beamer_template_zip_path=beamer_template_zip_path,
        formal_letter_template_zip_path=formal_letter_template_zip_path,
        isi_phd_thesis_template_zip_path=isi_phd_thesis_template_zip_path
    )

@misc_bp.route('/isi_symposium_25')
def isi_symposium_25():
    return render_template('isi_symposium_25.html')

@misc_bp.route('/isi_symposium_26')
def isi_symposium_26():
    return render_template('isi_symposium_26.html')

@misc_bp.route('/symposiums')
def symposiums():
    return render_template('symposiums.html')