from flask import render_template, redirect, flash, g
from flask_login import current_user
from flask import Blueprint

from cl_int.findolt import FindOlt
from cl_int.findonu import FindOnu
from cl_int.actonu import ActionOnu
from cl_other.conn_olt import ConnOLT
from db_services.db_users import UsersServiceDb
from db_services.db_cfg import CfgServiceDb
from db_services.db_olt import OltServiceDb
from db_services.db_history import HistoryServiceDb
from services.logger import log_write


onuinfo_bp = Blueprint('onuinfo', __name__, url_prefix='/onuinfo')


@onuinfo_bp.before_request
def login_required_for_all_routes():
    pass


@onuinfo_bp.route("/<int:oltid>/<string:onu>/history/delete")
def delete_onu_history(oltid, onu):
    '''
    Удалить историю сигналов из базы
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)

    oltinfo = OltServiceDb().get_olt(oltid)
    if any(userinfo['groupname'] == n for n in ['Administrator', 'default', oltinfo.group.group_name]):
        pass
    else:
        return redirect('/forbidden')

    result = HistoryServiceDb().delete_history(oltid, onu)
    flash(result)
    log_write(f"User: {userinfo['username']}; Action: CLEAR_ONU_HISTORY; Message: {result['message']}")

    return redirect(f'/onuinfo/{oltid}/{onu}/history')


@onuinfo_bp.route('/<string:onu>')
def onuinfo(onu):
    '''
    Информация об ОНУ 
    '''
    try:
        userid = current_user.get_id()
        userinfo = UsersServiceDb().get_user(userid)
        onurequest = FindOnu(onu, userinfo)
        onu_info = onurequest.onuinfo()
        return render_template('/onuinfo.html', onu_info=onu_info)
    
    except TypeError:
        onu = f"Неправильный мак или серийный номер: {onu}"
        return render_template("/onunotfound.html", onu=onu)

    except ValueError:
        onu = f"Ону {onu} не найдена"
        return render_template("/onunotfound.html", onu=onu)
    

@onuinfo_bp.route("/<int:oltid>/<string:onu>/catvon")
def onu_catvon(oltid, onu):
    '''
    Включить CATV порт
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    onurequest = ActionOnu(onu, oltid, userinfo)
    onurequest.onucatvon()
    
    log_write(f"User: {userinfo['username']}; Action: CATV_ON; Message: CATV порт на ОНУ {onu} включен")
    return redirect(f'/onuinfo/{onu}')


@onuinfo_bp.route("/<int:oltid>/<string:onu>/catvoff")
def onu_catvoff(oltid, onu):
    '''
    Выключить CATV порт
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    onurequest = ActionOnu(onu, oltid, userinfo)
    onurequest.onucatvoff()
    
    log_write(f"User: {userinfo['username']}; Action: CATV_OFF; Message: CATV порт на ОНУ {onu} выключен")
    return redirect(f'/onuinfo/{onu}')
       

@onuinfo_bp.route("/<int:oltid>/<string:onu>/reboot")
def onu_reboot(oltid, onu):
    ''' 
    Перезагрузка ОНУ
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    
    onurequest = ActionOnu(onu, oltid, userinfo)
    result = onurequest.onureboot()
    flash(result)
    
    log_write(f"User: {userinfo['username']}; Action: REBOOTED_ONU; Message: {result['message']}")
    
    return redirect(f'/onuinfo/{onu}')


@onuinfo_bp.route("/<int:oltid>/<string:onu>/deleteonu")
def onu_delete(oltid, onu):
    ''' 
    Удалить ОНУ с ОЛТа
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    try:
        olt_find = FindOlt(userinfo, oltid) 
        olt_information = olt_find.oltinfo()
    except ValueError:
        return redirect('/forbidden')
    
    snmp_cfg = CfgServiceDb()
    cfg = snmp_cfg.get_cfg()
    PF_HUAWEI = cfg['PL_H']
    try:
        if PF_HUAWEI in olt_information['platform']:     
            onurequest = ConnOLT(olt_information, onu, g.CONN)
            conf_onu_info = onurequest.confonuhuawei()
            
            onurequest = ActionOnu(onu, oltid, userinfo, confonu=conf_onu_info['outconf'])
            result = onurequest.onudelete()
            flash(result)

        else:
            onurequest = ActionOnu(onu, oltid, userinfo)
            result = onurequest.onudelete()
            flash(result)

    except:
        log_write(f"User: {userinfo['username']}; Action: DELETE_ONU; Message: Ошибка. Не получилось подключиться к ОЛТу по Telnet/SSH")
        flash({'result': 'error', 'message': 'Ошибка. Не получилось подключиться к ОЛТу по Telnet/SSH'})

        return redirect(f"/onuinfo/{onu}")
 
    log_write(f"User: {userinfo['username']}; Action: DELETE_ONU; Message: {result['message']}")        
    return redirect(f'/oltinfo/{oltid}')


@onuinfo_bp.route("/<int:oltid>/<string:onu>/history")
def show_onu_history(oltid, onu):
    '''
    Получить историю сигналов из базы
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)

    oltinfo = OltServiceDb().get_olt(oltid)
    if any(userinfo['groupname'] == n for n in ['Administrator', 'default', oltinfo.group.group_name]):
        pass
    else:
        return redirect('/forbidden')

    history = HistoryServiceDb().get_history(oltid, onu)
    
    return render_template('onuhistory.html', history=history, onu=onu, oltid=oltid)