from flask import render_template, redirect, flash, g
from flask_login import login_required, current_user
from flask import Blueprint

from cl_int.findolt import FindOlt
from db_services.db_users import UsersServiceDb


oltinfo_bp = Blueprint('oltinfo', __name__, url_prefix='/oltinfo')


@oltinfo_bp.before_request
@login_required
def login_required_for_all_routes():
    pass


@oltinfo_bp.route("/<int:id>")
def olt_info(id):
    '''
    Страница просмотра информации об ОЛТе
    '''
    try:
        userid = current_user.get_id()
        userinfo = UsersServiceDb().get_user(userid)
        olt_find = FindOlt(userinfo, olt_id=id)
        olt_information = olt_find.oltinfo()

        return render_template("oltinfo.html", olt_information=olt_information)
    except ValueError:
        return redirect('/forbidden')


@oltinfo_bp.route("/<int:id>/update")
def olt_update(id):
    ''' 
    Опрос конкретного ОЛТа
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    try:
        olt_find = FindOlt(userinfo, id)
        result = olt_find.update_olt()
        flash(result)
        return redirect(f'/oltinfo/{id}')
    except ValueError:
        return redirect('/forbidden')


@oltinfo_bp.route("/<int:id>/<string:port>")
def olt_port_info(id, port):
    '''
    Страница просмотра дерева
    '''
    olt_port = port.replace(".", "/")
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    try:
        olt_information = FindOlt(userinfo, id, olt_port)
        olt_info = olt_information.oltinfo()
        pon_status = olt_information.ponportstatus()
        
        return render_template(
                        "oltportinfo.html", 
                        pon_status=pon_status, 
                        olt_port=olt_port, 
                        olt_info=olt_info,
                    )

    except KeyError:
        flash("База устарела, опросите ОЛТ")
        return redirect(f"/oltinfo/{id}")
    except ValueError:
        return redirect('/forbidden')
        

