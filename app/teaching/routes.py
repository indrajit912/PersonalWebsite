# Routes for teaching bp
# Author: Indrajit Ghosh
# Created On: Dec 24, 2023
#

from . import teaching_bp

from flask import render_template


#######################################################
#                      Routes
#######################################################
@teaching_bp.route('/')
def index():
    return render_template('teaching.html')


@teaching_bp.route('/isibc/intro_to_cp_even_2024.html')
def intro_to_cp_even_2024():
    return render_template('isibc/intro_to_cp_even_2024.html')

@teaching_bp.route('/isibc/optimization_even2025.html')
def optimization_even2025():
    return render_template('isibc/optimization_bmathIII_2025.html')

@teaching_bp.route('/isibc/course_harmonic_even2024.html')
def course_harmonic_even2024():
    return render_template('isibc/course_harmonic_even2024.html')

@teaching_bp.route('/isibc/anal_several_vars_odd_2023.html')
def anal_several_vars_odd_2023_ta():
    return render_template('isibc/anal_several_vars_odd_2023.html')

@teaching_bp.route('/isibc/comp_anal_odd_sem_2022.html')
def comp_anal_odd_sem_2022_ta():
    return render_template('isibc/comp_anal_odd_sem_2022.html')

@teaching_bp.route('/isibc/func_anal_even_sem_2021.html')
def func_anal_even_sem_2021_ta():
    return render_template('isibc/func_anal_even_sem_2021.html')

@teaching_bp.route('/isibc/optimization_odd_sem_2021.html')
def optimization_odd_sem_2021_ta():
    return render_template('isibc/optimization_odd_sem_2021.html')

######################################################################