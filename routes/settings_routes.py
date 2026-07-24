from flask import render_template, request, redirect, flash, g
from flask_login import login_required, current_user
from flask import Blueprint

from cl_int.findolt import FindOlt
from db_services.db_users import UsersServiceDb
from db_services.db_onu import OnuServiceDb
from db_services.db_olt import OltServiceDb
from db_services.db_groups import GroupsServiceDb
from db_services.db_cfg import CfgServiceDb
from db_services.db_history import HistoryServiceDb
from services.showlogs import showlogs
from services.logger import log_write


LOGDIR = './'
LOGFILE = 'logging_oltshub.log'

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')


@settings_bp.before_request
@login_required
def login_required_for_all_routes():
    pass


@settings_bp.route('/profile', methods=['POST', 'GET'])
def profile():
    '''
    Профиль пользователя
    '''
    userid = current_user.get_id()
    user_profile = UsersServiceDb().get_user(userid)
    if request.method == 'POST':
        if request.form['psw'] == request.form['psw_repeat']:
            change_psw = UsersServiceDb()
            result = change_psw.changepsw(userid, request.form['psw'])
            flash(result)
            return redirect('/settings/profile')
        else:
            flash({'result': 'error', 'message': 'Ошибка. Пароли не совпадают!',})
            return redirect('/settings/profile')
    else:
        menu = g.menucfg.getmenucfg(user_profile['privilage'])
        return render_template('settings/settings_profile.html', user_profile=user_profile, menu=menu)


@settings_bp.route("/doubleonu")
def doubleonu():
    '''
    Поиск дубликатов ОНУ
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        doublemac, doublesn = OnuServiceDb().get_double_onu(userinfo)
        menu = g.menucfg.getmenucfg(userinfo['privilage'])
    
        return render_template('/settings/doubleonu.html', doublemac=doublemac, doublesn=doublesn, menu=menu)
    else:
        return redirect('/forbidden')
    

@settings_bp.route("/oltadd", methods=['POST', 'GET'])
def olt_add():
    '''
    Добавление нового ОЛТа (Если нет НетБокса) 
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        getcfg = CfgServiceDb()
        getgroups = GroupsServiceDb()
        groups = getgroups.get_groups()
        cfg = getcfg.get_cfg()
        PF_LIST = [cfg['PL_H'], cfg['PL_B'], cfg['PL_C']]
        menu = g.menucfg.getmenucfg(userinfo['privilage'])
        if request.method == "POST":
            olt = {
                'hostname': request.form['hostname'],
                'descr': request.form['descr'],
                'group_id': request.form['group'],
                'ip_address': request.form['ip_address'],
                'platform': request.form['platform'],
                'pon_type': request.form['pontype'],
                'snmp_read': request.form['snmpread'],
                'snmp_write': request.form['snmpwrite'],
                'conn_type': request.form['conntype'],
                'conn_login': request.form['connlogin'],
                'conn_psw': request.form['connpsw'],
            }

            olt_add = OltServiceDb()
            result = olt_add.create_olt(olt)
            flash(result)
            log_write(f"User: {userinfo['username']}; Action: OLT_ADD; Message: {result['message']}")
            return render_template("/settings/settings_oltadd.html", pf_list=PF_LIST, groups=groups, menu=menu)

        else:
            return render_template("/settings/settings_oltadd.html", pf_list=PF_LIST, groups=groups, menu=menu)

    else:
        return redirect('/forbidden')
    

@settings_bp.route("/allhistory")
def show_all_history():
    '''
    Просмотр всей истории сигналов
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        menu = g.menucfg.getmenucfg(userinfo['privilage'])
        history = HistoryServiceDb().get_all_history()
        return render_template('/settings/onuhistory_all.html', menu=menu, history=history)
    else:
        return redirect('/forbidden')
    

@settings_bp.route('/oltslist')
def oltslist():
    '''
    Получение списка ОЛТов для редактирования
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        oltslist = OltServiceDb.get_olts()
        menu = g.menucfg.getmenucfg(userinfo['privilage'])

        return render_template("settings/settings_oltslist.html", menu=menu, oltslist=oltslist)
    
    else:   
        return redirect('/forbidden')
    

@settings_bp.route('/tokens')
def settingsapi():
    '''
    Работа с API
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        menu = g.menucfg.getmenucfg(userinfo['privilage'])

        return render_template("settings/settings_tokens.html", menu=menu)
    
    else:   
        return redirect('/forbidden')
    

@settings_bp.route('/showlogs')
def show_logs():
    '''
    Просмотр логов
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        logs = showlogs(f'{LOGDIR}{LOGFILE}')
        menu = g.menucfg.getmenucfg(userinfo['privilage'])
        return render_template('/settings/showlogs.html', logs=logs, menu=menu)
    else:   
        return redirect('/forbidden')
    

@settings_bp.route('/deluser/<int:user_id>')
def olthub_deluser(user_id):
    '''
    Удалить пользователя
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        deluser = UsersServiceDb()
        result = deluser.del_user(user_id)
        flash(result)
        log_write(f"User: {userinfo['username']}; Action: DEL_USER; Message: {result['message']} ")
        return redirect('/settings/adduser')
    else:
        return redirect('/forbidden')
    

@settings_bp.route('/user/<int:user_id>/edit', methods=['POST', 'GET'])
def olthub_edituser(user_id):
    '''
    Редактировать пользователя
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        if request.method == "POST":
            if request.form['psw']:
                if request.form['psw'] == request.form['psw_repeat']:
                    change_psw = UsersServiceDb()
                    result = change_psw.changepsw(user_id, request.form['psw'])
                    if result['result'] == 'error':
                        flash(result)
                        return redirect(f'/settings/user/{user_id}/edit')
                else:
                    flash({'result': 'error', 'message': 'Ошибка. Пароли не совпадают!',})
                    return redirect(f'/settings/user/{user_id}/edit')

            edituser = {
                'id':        user_id,
                'username':  request.form['username'],
                'group_id':  request.form['group_id'],
                'privilage': request.form['privilage'],
            }
            
            edit_user = UsersServiceDb()
            result = edit_user.edit_user(edituser)
            flash(result)
            log_write(f"User: {userinfo['username']}; Action: EDIT_USER; Message: {result['message']}")
            return redirect('/settings/adduser')
        else:
            menu = g.menucfg.getmenucfg(userinfo['privilage'])
            getuser = UsersServiceDb()
            user = getuser.get_user(user_id)
            getgroups = GroupsServiceDb()
            groups = getgroups.get_groups()
            return render_template('/settings/settings_useredit.html', user=user, menu=menu, groups=groups)

    else:
        return redirect('/forbidden')
    

@settings_bp.route('/adduser', methods=['POST', 'GET'])
def olthub_adduser():
    '''
    Добавить пользователя
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        if request.method == "POST":
            useradd = {
                'username':  request.form['username'],
                'psw':       request.form['psw'],
                'group_id':  request.form['group_id'],
                'privilage': request.form['privilage'],
            }
            
            add_user = UsersServiceDb()
            result = add_user.add_user(useradd)
            flash(result)
            log_write(f"User: {userinfo['username']}; Action: ADD_USER; Message: {result['message']}")
            return redirect('/settings/adduser')
        else:
            menu = g.menucfg.getmenucfg(userinfo['privilage'])
            getusers = UsersServiceDb()
            users = getusers.get_users()
            getgroups = GroupsServiceDb()
            groups = getgroups.get_groups()
            return render_template('/settings/settings_users.html', users=users, menu=menu, groups=groups)
    else:
        return redirect('/forbidden')
    

@settings_bp.route('/groups/<int:group_id>/del')
def olthub_delgroup(group_id):
    '''
    Удалить группу
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        delgroup = GroupsServiceDb()
        result = delgroup.del_group(group_id)
        flash(result)
        log_write(f"User {userinfo['username']} deleted group {result['group']}")
        return redirect('/settings/groups')
    else:
        return redirect('/forbidden')
    

@settings_bp.route('/groups', methods=['POST', 'GET'])
def olthub_addgroup():
    '''
    Добавить группу
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        if request.method == "POST":
            groupname = request.form['groupname']
            add_group = GroupsServiceDb()
            result = add_group.add_group(groupname)
            flash(result)
            log_write(f"User: {userinfo['username']}; Action: ADD_GROUP; Message: {result}")
            
            return redirect('/settings/groups')
        else:
            menu = g.menucfg.getmenucfg(userinfo['privilage'])
            getgroups = GroupsServiceDb()
            groups = getgroups.get_groups()
            
            return render_template('settings/settings_groups.html', groups=groups, menu=menu)
    else:
        return redirect('/forbidden')
    

@settings_bp.route('/cfgnb', methods=['POST', 'GET'])
def olthub_settings_nb():
    '''
    Конфигурация NetBox
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        if request.method == "POST":
            nb_cfg = {
                'api_key': request.form['api_key'],
                'epon_tag': request.form['tag_epon'],
                'gpon_tag': request.form['tag_gpon'],
                'urlnb': request.form['urlnb'],
                'pl_h': request.form['pl_h'],
                'pl_b': request.form['pl_b'],
                'pl_c': request.form['pl_c'],
            }
            setnbcfg = CfgServiceDb()
            result = setnbcfg.insertcfgnb(nb_cfg)
            flash(result)
            log_write(f"User: {userinfo['username']}; Action: CHANGE_NB_CONF; Message: {result['message']}")

            return redirect('/settings/cfgnb')
        else:
            menu = g.menucfg.getmenucfg(userinfo['privilage'])
            nbcfg = CfgServiceDb()
            cfg = nbcfg.get_cfg()
            key = cfg['API_KEY']
            cfg['API_KEY'] = 15*'*' + key[-5:]
            return render_template('/settings/settings_nb.html', cfg=cfg, menu=menu)
    else:
        return redirect('/forbidden')
    

@settings_bp.route('/cfgsnmp', methods=['POST', 'GET'])
def olthub_settings_snmp():
    '''
    Конфигурация SNMP
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        if request.method == "POST":
            snmp_cfg = {
                'snmp_read_h': request.form['snmp_read_h'],
                'snmp_write_h': request.form['snmp_write_h'],
                'snmp_read_b': request.form['snmp_read_b'],
                'snmp_write_b': request.form['snmp_write_b'],
                'snmp_read_c': request.form['snmp_read_c'],
                'snmp_write_c': request.form['snmp_write_c'],
            }
            setsnmpcfg = CfgServiceDb()
            result = setsnmpcfg.insert_cfg_snmp(snmp_cfg)
            flash(result)
            log_write(f"User: {userinfo['username']}; Action: CHANGE_SNMP_CONF; Message: {result['message']}")

            return redirect('/settings/cfgsnmp')
        else:
            menu = g.menucfg.getmenucfg(userinfo['privilage'])
            nbcfg = CfgServiceDb()
            cfg = nbcfg.get_cfg()
            return render_template('/settings/settings_snmp.html', cfg=cfg, menu=menu)
    else:   
        return redirect('/forbidden')
    

@settings_bp.route("/settings/allhistory/delete")
def delete_all_history():
    '''
    Очистить всю таблицу с иторией сигналов
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        result = HistoryServiceDb().delete_all_history()
        flash(result)
        log_write(f"User: {userinfo['username']}; Action: CLEAR_ALL_HISTORY; Message: {result['message']}")
        return redirect('/settings/allhistory')
    else:
        return redirect('/forbidden')


@settings_bp.route("/<int:id>/edit", methods=['POST', 'GET'])
def olt_edit(id):
    '''
    Редактирование ОЛТа
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        olt_find = FindOlt(userinfo, id) 
        olt_information = olt_find.oltinfo()
        olt_information['connpsw'] = '*1*1*' if olt_information['connpsw'] else ''

        getcfg = CfgServiceDb()
        getgroups = GroupsServiceDb()
        groups = getgroups.get_groups()
        cfg = getcfg.get_cfg()
        PF_LIST = [cfg['PL_H'], cfg['PL_B'], cfg['PL_C']]
        menu = g.menucfg.getmenucfg(userinfo['privilage'])
        if request.method == "POST":
            olt = {
                'id': id,
                'hostname': request.form['hostname'],
                'descr': request.form['descr'],
                'group_id': request.form['group'],
                'ip_address': request.form['ip_address'],
                'platform': request.form['platform'],
                'pon_type': request.form['pontype'],
                'snmp_read': request.form['snmpread'],
                'snmp_write': request.form['snmpwrite'],
                'conn_type': request.form['conntype'],
                'conn_login': request.form['connlogin'],
                'conn_psw': 'None' if request.form['connpsw'] == '*1*1*' else request.form['connpsw'],
            }

            olt_add = OltServiceDb()
            result = olt_add.edit_olt(olt)
            flash(result)
            log_write(f"User: {userinfo['username']}; Action: OLT_EDITED; Message: {result['message']}")
            return redirect(f"/settings/{id}/edit")

        else:
            return render_template("/settings/settings_oltedit.html", pf_list=PF_LIST, groups=groups, menu=menu, olt_information=olt_information)

    else:
        return redirect('/forbidden')
    

@settings_bp.route("/<int:id>/delete")
@login_required
def olt_delete(id):
    '''
    Удаление ОЛТа
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':    
        olt_del = OltServiceDb()
        result = olt_del.delete_olt(id)
        flash(result)
        log_write(f"User: {userinfo['username']}; Action: OLT_DELETE; Message: {result['message']}")
        return redirect("/settings/oltslist")
    else:
        flash({'result': 'error', 'message': 'Ошибка! У вас недостаточно прав для удаления ОЛТа!'})
        log_write(f"User: {userinfo['username']}; Action: OLT_DELETE; Message: Недостаточно прав для удаления ОЛТа.")
        return redirect(f'/oltinfo/{id}')
    
