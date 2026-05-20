from flask import Flask, render_template, request, redirect, flash
from flask_restful import Api, Resource
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import os
import logging.handlers
from dotenv import load_dotenv
from werkzeug.security import check_password_hash

from cl_int.findonu import FindOnu
from cl_int.actonu import ActionOnu
from funcs.get_olts import get_netbox_olt_list
from models.base import db
from cl_int.findolt import FindOlt
from db_services.db_cfg import CfgServiceDb
from db_services.userlogin import UserLogin
from cl_other.conn_olt import ConnOLT
from cl_other.show_logs import ShowLogs
from funcs.showlogs import showlogs
from db_services.db_olt import OltServiceDb
from db_services.db_onu import OnuServiceDb
from db_services.db_groups import GroupsServiceDb
from db_services.db_users import UsersServiceDb
from db_services.db_menucfg import MenuServiceDb


load_dotenv()

IP_SRV = os.getenv('IP_SRV')
PORT_SRV = os.getenv('PORT_SRV')
DEBUG = os.getenv('DEBUG', "False").lower() in ("true", "1", "t")

DATABASE = os.getenv('DATABASE')

LOGDIR = './'
LOGFILE = 'logging_oltshub.log'

#Доступы к ОЛТам по SSH/Telnet
CONN = {
    'BDCOM_LOGIN':  os.getenv('BDCOM_LOGIN'),
    'BDCOM_PSW':    os.getenv('BDCOM_PSW'),
    'HUAWEI_LOGIN': os.getenv('HUAWEI_LOGIN'),
    'HUAWEI_PSW':   os.getenv('HUAWEI_PSW'),
    'CDATA_LOGIN':  os.getenv('CDATA_LOGIN'),
    'CDATA_PSW':    os.getenv('CDATA_PSW'),
}

app = Flask(__name__)
api = Api()
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['APP_VERSION'] = 'v3.1'

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = {'result': 'error', 'message': 'Авторизуйтесь для доступа к сайту'}


logger = logging.getLogger('OLTsHUB')
logger.setLevel(logging.DEBUG)
logfile = logging.handlers.RotatingFileHandler(
    f'{LOGDIR}{LOGFILE}', maxBytes=500000, backupCount=3)
logfile.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logfile.setFormatter(formatter)
logger.addHandler(logfile)

db.init_app(app)


class Main_Api(Resource):
    def get(self, onu):
        if current_user.is_authenticated:
            onurequest = FindOnu(onu)
            onu_info = onurequest.onuinfo()

            return onu_info


api.add_resource(Main_Api, "/api/onuinfo/<string:onu>")
api.init_app(app)


dbase = None
menucfg = None
@app.before_request
def before_request():
    global dbase
    global menucfg
    dbase = UsersServiceDb()
    menucfg = MenuServiceDb()


@app.context_processor
def inject_version():
    return dict(version=app.config['APP_VERSION'])


@login_manager.user_loader
def load_user(user_id):
    return UserLogin().fromDB(user_id)


@app.route('/login', methods=['POST', 'GET'])
def login():
    '''
    Страница входа
    '''
    # Если пользователь авторизован, то редирект в профиль
    if current_user.is_authenticated:
        return redirect('/settings/profile')
    # Если не авторизован, то открывается страница входа
    if request.method == 'POST':
        user = dbase.get_user_by_name(request.form['username'])
        if user and check_password_hash(user['psw'], request.form['psw']):
            userlogin = UserLogin().create(user)
            rm = True if request.form.get('remember-me') else False
            login_user(userlogin, remember=rm)
            flash({'result': 'success', 'message': 'Успешный вход в систему',})
            logger.info(f"User: {request.form['username']}; Action: LOGIN; Message: Успешный вход в систему")
            return redirect(request.args.get('next') or '/')
        else:
            logger.info(f"User: {request.form['username']}; Action: LOGIN; Message: Неправильный логин/пароль")
            flash({'result': 'error', 'message': 'Неправильный логин/пароль',})
            return redirect('/login')
    else:    
        return render_template('/login.html')


@app.route('/logout')
@login_required
def logout():
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    logout_user()
    logger.info(f"User: {userinfo['username']}; Action: LOGOUT; Message: Выход из системы")
    flash({'result': 'success', 'message': 'Вы вышли из аккаунта',})
    return redirect('/login')


@app.route('/settings/profile', methods=['POST', 'GET'])
@login_required
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
        menu = menucfg.getmenucfg(user_profile['privilage'])
        return render_template('settings/settings_profile.html', user_profile=user_profile, menu=menu)


@app.route("/", methods=['POST', 'GET'])
@login_required
def index():
    '''
    Главная страница, получение через строку поиска мака или серийника ОНУ
    и дальнейшая обработка
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if request.method == "POST":
        try:
            onu = request.form['searchonu']
            onurequest = FindOnu(onu, userinfo)
            onu_info = onurequest.onuinfo()

            return render_template("/onuinfo.html", onu_info=onu_info)
           
        except TypeError:
            onu = f"Неправильный мак или серийный номер: {onu}"
            return render_template("/onunotfound.html", onu=onu)

        except ValueError:
            onu = f"Ону {onu} не найдена"
            return render_template("/onunotfound.html", onu=onu)

    else:
        olts_list = OltServiceDb.get_olts()
        if userinfo['privilage'] == 'Administrator':    
            return render_template("index.html", oltslist=olts_list)
        else:
            oltslist = []
            for i in olts_list:
                if i['group'] == userinfo['groupname']:
                    oltslist.append(
                        {
                            'id': i['id'],
                            'hostname': i['hostname'],
                            'descr': i['descr'],
                            'ip_address': i['ip_address'],
                        }
                    )
            return render_template("index.html", oltslist=oltslist)


@app.route("/help")
def help_page():
    '''
    Страница справки
    '''
    return render_template("help.html")


@app.route('/onuinfo/<string:onu>')
@login_required
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


@app.route("/oltinfo/<int:id>")
@login_required
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


@app.route("/oltinfo/<int:id>/<string:port>")
@login_required
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


@app.route("/oltinfo/<int:id>/update")
@login_required
def olt_update(id):
    ''' 
    Опрос конкретного ОЛТа
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    try:
        olt_find = FindOlt(userinfo, id)
        olt_find.update_olt()
        flash({'result': 'success', 'message': 'ОЛТ опрошен',})
        return redirect(f'/oltinfo/{id}')
    except ValueError:
        return redirect('/forbidden')


@app.route("/oltupdate/<int:id>")
@login_required
def updateolt(id):
    ''' 
    Опрос конкретного ОЛТа с главной страницы
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    try:
        olt_find = FindOlt(userinfo, id)
        olt_find.update_olt()
        flash({'result': 'success', 'message': 'ОЛТ опрошен',})
        return redirect('/')
    except ValueError:
        return redirect('/forbidden')


@app.route("/oltslistupdate")
@login_required
def oltslistupdate():
    '''
    Получить список ОЛТов из НетБокса
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        try:
            get_netbox_olt_list()
            flash({'result': 'success', 'message': 'Получен список ОЛТов из NetBox',})
            logger.info(f"User: {userinfo['username']}; Action: GET_OLTS_FROM_NB; Message: Получен список ОЛТов из NetBox!")
            return redirect('/')

        except:
            logger.info(f" \
                User: {userinfo['username']}; \
                Action: GET_OLTS_FRON_NB; \
                Message: Ошибка. Убедитесь, что настройки для NetBox правильные!" \
            )
            flash({
                'result': 'error', 
                'message': 'Ошибка. Убедитесь, что настройки для NetBox правильные!',
                }
            )
            return redirect('/settings/cfgnb')
    else:
        return redirect('/forbidden')


@app.route("/oltsupdate")
@login_required
def oltsupdate():
    '''
    Опросить ВСЕ ОЛТы
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        olts_list = OltServiceDb.get_olts()
        for o in olts_list:
            olt_find = FindOlt(userinfo, o['id'])
            olt_find.update_olt()

        flash({'result': 'success', 'message': 'Опрос ОЛТов завершён'})
        logger.info(f"User: {userinfo['username']}; Action: UPDATE_ALL_OLTS; Message: Опрошены все ОЛТы из базы")
        return redirect('/settings/oltslist')
    else:
        return redirect('/forbidden')
   

@app.route("/settings/doubleonu")
@login_required
def doubleonu():
    '''
    Поиск дубликатов ОНУ
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        doublemac, doublesn = OnuServiceDb().get_double_onu(userinfo)
        menu = menucfg.getmenucfg(userinfo['privilage'])
    
        return render_template('/settings/doubleonu.html', doublemac=doublemac, doublesn=doublesn, menu=menu)
    else:
        return redirect('/forbidden')


@app.errorhandler(404)
def pagenotfound(error):
    '''
    Страница 404
    '''
    return render_template('page404.html', title="Страница не найдена")


@app.route('/forbidden')
def pageforbidden():
    '''
    Страница запрета доступа
    '''
    return render_template('/forbidden.html', title='Доступ запрещён')


@app.route("/onuinfo/<int:oltid>/<string:onu>/catvon")
@login_required
def onu_catvon(oltid, onu):
    '''
    Включить CATV порт
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    onurequest = ActionOnu(onu, oltid, userinfo)
    onurequest.onucatvon()
    
    logger.info(f"User: {userinfo['username']}; Action: CATV_ON; Message: CATV порт на ОНУ {onu} включен")
    return redirect(f'/onuinfo/{onu}')


@app.route("/onuinfo/<int:oltid>/<string:onu>/catvoff")
@login_required
def onu_catvoff(oltid, onu):
    '''
    Выключить CATV порт
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    onurequest = ActionOnu(onu, oltid, userinfo)
    onurequest.onucatvoff()
    
    logger.info(f"User: {userinfo['username']}; Action: CATV_OFF; Message: CATV порт на ОНУ {onu} выключен")
    return redirect(f'/onuinfo/{onu}')


@app.route("/settings/oltadd", methods=['POST', 'GET'])
@login_required
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
        menu = menucfg.getmenucfg(userinfo['privilage'])
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
            logger.info(f"User: {userinfo['username']}; Action: OLT_ADD; Message: {result['message']}")
            return render_template("/settings/settings_oltadd.html", pf_list=PF_LIST, groups=groups, menu=menu)

        else:
            return render_template("/settings/settings_oltadd.html", pf_list=PF_LIST, groups=groups, menu=menu)

    else:
        return redirect('/forbidden')


@app.route("/oltinfo/<int:id>/delete")
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
        logger.info(f"User: {userinfo['username']}; Action: OLT_DELETE; Message: {result['message']}")
        return redirect("/settings/oltslist")
    else:
        flash({'result': 'error', 'message': 'Ошибка! У вас недостаточно прав для удаления ОЛТа!'})
        logger.info(f"User: {userinfo['username']}; Action: OLT_DELETE; Message: Недостаточно прав для удаления ОЛТа.")
        return redirect(f'/oltinfo/{id}')
    

@app.route("/oltinfo/<int:id>/edit", methods=['POST', 'GET'])
@login_required
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
        menu = menucfg.getmenucfg(userinfo['privilage'])
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
            logger.info(f"User: {userinfo['username']}; Action: OLT_EDITED; Message: {result['message']}")
            return redirect(f"/oltinfo/{id}/edit")

        else:
            return render_template("/settings/settings_oltedit.html", pf_list=PF_LIST, groups=groups, menu=menu, olt_information=olt_information)

    else:
        return redirect('/forbidden')
        


@app.route("/onuinfo/<int:oltid>/<string:onu>/reboot")
@login_required
def onu_reboot(oltid, onu):
    ''' 
    Перезагрузка ОНУ
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    
    onurequest = ActionOnu(onu, oltid, userinfo)
    result = onurequest.onureboot()
    flash(result)
    
    logger.info(f"User: {userinfo['username']}; Action: REBOOTED_ONU; Message: {result['message']}")
                
    return redirect(f'/onuinfo/{onu}')


@app.route("/onuinfo/<int:oltid>/<string:onu>/deleteonu")
@login_required
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
            onurequest = ConnOLT(olt_information, onu, CONN)
            conf_onu_info = onurequest.confonuhuawei()
            
            onurequest = ActionOnu(onu, oltid, userinfo, confonu=conf_onu_info['outconf'])
            result = onurequest.onudelete()
            flash(result)

        else:
            onurequest = ActionOnu(onu, oltid, userinfo)
            result = onurequest.onudelete()
            flash(result)

    except:
        logger.info(f"User: {userinfo['username']}; Action: DELETE_ONU; Message: Ошибка. Не получилось подключиться к ОЛТу по Telnet/SSH")
        flash({'result': 'error', 'message': 'Ошибка. Не получилось подключиться к ОЛТу по Telnet/SSH'})

        return redirect(f"/onuinfo/{onu}")
 
    logger.info(f"User: {userinfo['username']}; Action: DELETE_ONU; Message: {result['message']}'")
                
    return redirect(f'/oltinfo/{oltid}')


@app.route('/settings/cfgsnmp', methods=['POST', 'GET'])
@login_required
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
            logger.info(f"User: {userinfo['username']}; Action: CHANGE_SNMP_CONF; Message: {result['message']}")

            return redirect('/settings/cfgsnmp')
        else:
            menu = menucfg.getmenucfg(userinfo['privilage'])
            nbcfg = CfgServiceDb()
            cfg = nbcfg.get_cfg()
            return render_template('/settings/settings_snmp.html', cfg=cfg, menu=menu)
    else:   
        return redirect('/forbidden')


@app.route('/settings/cfgnb', methods=['POST', 'GET'])
@login_required
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
            logger.info(f"User: {userinfo['username']}; Action: CHANGE_NB_CONF; Message: {result['message']}")

            return redirect('/settings/cfgnb')
        else:
            menu = menucfg.getmenucfg(userinfo['privilage'])
            nbcfg = CfgServiceDb()
            cfg = nbcfg.get_cfg()
            key = cfg['API_KEY']
            cfg['API_KEY'] = 15*'*' + key[-5:]
            return render_template('/settings/settings_nb.html', cfg=cfg, menu=menu)
    else:
        return redirect('/forbidden')


@app.route('/settings/groups', methods=['POST', 'GET'])
@login_required
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
            logger.info(f"User: {userinfo['username']}; Action: ADD_GROUP; Message: {result}")
            
            return redirect('/settings/groups')
        else:
            menu = menucfg.getmenucfg(userinfo['privilage'])
            getgroups = GroupsServiceDb()
            groups = getgroups.get_groups()
            
            return render_template('settings/settings_groups.html', groups=groups, menu=menu)
    else:
        return redirect('/forbidden')
    

@app.route('/settings/groups/<int:group_id>/del')
@login_required
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
        logger.info(f"User {userinfo['username']} deleted group {result['group']}")
        return redirect('/settings/groups')
    else:
        return redirect('/forbidden')   


@app.route('/settings/adduser', methods=['POST', 'GET'])
@login_required
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
            logger.info(f"User: {userinfo['username']}; Action: ADD_USER; Message: {result['message']}")
            return redirect('/settings/adduser')
        else:
            menu = menucfg.getmenucfg(userinfo['privilage'])
            getusers = UsersServiceDb()
            users = getusers.get_users()
            getgroups = GroupsServiceDb()
            groups = getgroups.get_groups()
            return render_template('/settings/settings_users.html', users=users, menu=menu, groups=groups)
    else:
        return redirect('/forbidden')


@app.route('/settings/user/<int:user_id>/edit', methods=['POST', 'GET'])
@login_required
def olthub_edituser(user_id):
    '''
    Редактировать пользователя
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        if request.method == "POST":
            edituser = {
                'id':        user_id,
                'username':  request.form['username'],
                'group_id':  request.form['group_id'],
                'privilage': request.form['privilage'],
            }
            
            edit_user = UsersServiceDb()
            result = edit_user.edit_user(edituser)
            flash(result)
            logger.info(f"User: {userinfo['username']}; Action: EDIT_USER; Message: {result['message']}")
            return redirect('/settings/adduser')
        else:
            menu = menucfg.getmenucfg(userinfo['privilage'])
            getuser = UsersServiceDb()
            user = getuser.get_user(user_id)
            getgroups = GroupsServiceDb()
            groups = getgroups.get_groups()
            return render_template('/settings/settings_useredit.html', user=user, menu=menu, groups=groups)

    else:
        return redirect('/forbidden')


@app.route('/settings/deluser/<int:user_id>')
@login_required
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
        logger.info(f"User: {userinfo['username']}; Action: DEL_USER; Message: {result['message']} ")
        return redirect('/settings/adduser')
    else:
        return redirect('/forbidden')


@app.route('/onuconfinfo/<int:oltid>/<string:onu>')
@login_required
def onuconfinfo(oltid, onu):
    '''
    Просмотр конфигурации ОНУ
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    try:
        olt_find = FindOlt(userinfo, oltid) 
        olt_information = olt_find.oltinfo()
    except ValueError:
        return redirect('/forbidden')
    
    try:
        onurequest = ConnOLT(olt_information, onu, CONN)
        conf_onu_info = onurequest.confonuinfo()
    except:
        logger.info(f"User: {userinfo['username']}; Action: SHOW_ONU_CONF; Message: Не получилось посмотреть конфигурацию ОНУ {onu}")
        flash({'result': 'error', 'message': 'Ошибка. Не получилось подключиться к ОЛТу по Telnet/SSH'})

        return redirect(f"/onuinfo/{onu}")

    logger.info(f"User: {userinfo['username']}; Action: SHOW_ONU_CONF; Message: Просмотр конфигурации ОНУ {onu}")

    return render_template('/onuconfinfo.html', conf_onu_info=conf_onu_info)


@app.route('/oltshowlogs/<int:id>')
@login_required
def oltlogs(id):
    '''
    Просмотр логов ОЛТа
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    try:
        olt_find = FindOlt(userinfo, id) 
        olt_information = olt_find.oltinfo()
    except ValueError:
        return redirect('/forbidden')
    
    try:
        logsrequest = ShowLogs(olt_information, CONN)
        logs_info = logsrequest.showlogs()
    except:
        logger.info(f"User: {userinfo['username']}; \
                Action: SHOWLOGS; Message: Ошибка. \
                Не получилось подключиться к ОЛТу {olt_information['ip_address']} по Telnet/SSH")
        flash({'result': 'error', 'message': 'Ошибка. Не получилось подключиться к ОЛТу по Telnet/SSH'})

        return redirect(f"/oltinfo/{id}")

    logger.info(f"User: {userinfo['username']}; Action: SHOWLOGS; Message: Просмотр логов ОЛТа {olt_information['ip_address']}")

    return render_template('/oltshowlogs.html', logs_info=logs_info)


@app.route('/settings/showlogs')
@login_required
def show_logs():
    '''
    Просмотр логов
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        logs = showlogs(f'{LOGDIR}{LOGFILE}')
        menu = menucfg.getmenucfg(userinfo['privilage'])
        return render_template('/settings/showlogs.html', logs=logs, menu=menu)
    else:   
        return redirect('/forbidden')
    

@app.route('/settings/oltslist')
@login_required
def oltslist():
    '''
    Получение списка ОЛТов для редактирования
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        oltslist = OltServiceDb.get_olts()
        menu = menucfg.getmenucfg(userinfo['privilage'])

        return render_template("settings/settings_oltslist.html", menu=menu, oltslist=oltslist)
    
    else:   
        return redirect('/forbidden')
    

@app.route('/settings/tokens')
@login_required
def settingsapi():
    '''
    Работа с API
    '''
    userid = current_user.get_id()
    userinfo = UsersServiceDb().get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        menu = menucfg.getmenucfg(userinfo['privilage'])

        return render_template("settings/settings_tokens.html", menu=menu)
    
    else:   
        return redirect('/forbidden')


if __name__ == "__main__":
    app.run(debug=DEBUG, host=IP_SRV, port=PORT_SRV)