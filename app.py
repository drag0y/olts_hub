from flask import Flask, render_template, request, redirect, flash, g
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import os
from dotenv import load_dotenv
from werkzeug.security import check_password_hash

from cl_int.findonu import FindOnu
from services.get_olts import get_netbox_olt_list
from models.base import db
from cl_int.findolt import FindOlt
from db_services.userlogin import UserLogin
from cl_olt.conn_olt import ConnOLT
from services.show_logs import ShowLogs
from services.showlogs import showlogs
from db_services.db_olt import OltServiceDb
from db_services.db_users import UsersServiceDb
from db_services.db_menucfg import MenuServiceDb
from routes.settings_routes import settings_bp
from routes.oltinfo_routes import oltinfo_bp
from routes.onuinfo_routes import onuinfo_bp
from api.api_onuinfo import api_onuinfo_bp
from services.logger import log_write


load_dotenv()

IP_SRV = os.getenv('IP_SRV')
PORT_SRV = os.getenv('PORT_SRV')
DEBUG = os.getenv('DEBUG', "False").lower() in ("true", "1", "t")

DATABASE = os.getenv('DATABASE')

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['APP_VERSION'] = 'v3.4'

app.json.ensure_ascii = False
app.config.update({
    'RESTFUL_JSON': {
        'ensure_ascii': False
    }
})

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = {'result': 'error', 'message': 'Авторизуйтесь для доступа к сайту'}

db.init_app(app)

@app.before_request
def before_request():
    g.userbase = UsersServiceDb()
    g.menucfg = MenuServiceDb()
    #Доступы к ОЛТам по SSH/Telnet
    g.CONN = {
        'BDCOM_LOGIN':  os.getenv('BDCOM_LOGIN'),
        'BDCOM_PSW':    os.getenv('BDCOM_PSW'),
        'HUAWEI_LOGIN': os.getenv('HUAWEI_LOGIN'),
        'HUAWEI_PSW':   os.getenv('HUAWEI_PSW'),
        'CDATA_LOGIN':  os.getenv('CDATA_LOGIN'),
        'CDATA_PSW':    os.getenv('CDATA_PSW'),
    }


app.register_blueprint(settings_bp)
app.register_blueprint(oltinfo_bp)
app.register_blueprint(onuinfo_bp)
app.register_blueprint(api_onuinfo_bp)


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
        user = g.userbase.get_user_by_name(request.form['username'])
        if user and check_password_hash(user['psw'], request.form['psw']):
            userlogin = UserLogin().create(user)
            rm = True if request.form.get('remember-me') else False
            login_user(userlogin, remember=rm)
            flash({'result': 'success', 'message': 'Успешный вход в систему',})
            log_write(f"User: {request.form['username']}; Action: LOGIN; Message: Успешный вход в систему")
            return redirect(request.args.get('next') or '/')
        else:
            log_write(f"User: {request.form['username']}; Action: LOGIN; Message: Неправильный логин/пароль")
            flash({'result': 'error', 'message': 'Неправильный логин/пароль',})
            return redirect('/login')
    else:    
        return render_template('/login.html')


@app.route('/logout')
@login_required
def logout():
    userid = current_user.get_id()
    userinfo = g.userbase.get_user(userid)
    logout_user()
    log_write(f"User: {userinfo['username']}; Action: LOGOUT; Message: Выход из системы")
    flash({'result': 'success', 'message': 'Вы вышли из аккаунта',})
    return redirect('/login')


@app.route("/", methods=['POST', 'GET'])
@login_required
def index():
    '''
    Главная страница, получение через строку поиска мака или серийника ОНУ
    и дальнейшая обработка
    '''
    userid = current_user.get_id()
    userinfo = g.userbase.get_user(userid)
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
        if userinfo['privilage'] == 'Administrator' or userinfo['groupname'] == 'default':    
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


@app.route("/oltupdate/<int:id>")
@login_required
def updateolt(id):
    ''' 
    Опрос конкретного ОЛТа с главной страницы
    '''
    userid = current_user.get_id()
    userinfo = g.userbase.get_user(userid)
    try:
        olt_find = FindOlt(userinfo, id)
        result = olt_find.update_olt()
        flash(result)
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
    userinfo = g.userbase.get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        try:
            get_netbox_olt_list()
            flash({'result': 'success', 'message': 'Получен список ОЛТов из NetBox',})
            log_write(f"User: {userinfo['username']}; Action: GET_OLTS_FROM_NB; Message: Получен список ОЛТов из NetBox!")
            return redirect('/')

        except:
            log_write(f" \
                User: {userinfo['username']}; \
                Action: GET_OLTS_FROM_NB; \
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
    userinfo = g.userbase.get_user(userid)
    if userinfo['privilage'] == 'Administrator':
        olts_list = OltServiceDb.get_olts()
        for o in olts_list:
            olt_find = FindOlt(userinfo, o['id'])
            olt_find.update_olt()

        flash({'result': 'success', 'message': 'Опрос ОЛТов завершён'})
        log_write(f"User: {userinfo['username']}; Action: UPDATE_ALL_OLTS; Message: Опрошены все ОЛТы из базы")
        return redirect('/settings/oltslist')
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


@app.route('/onuconfinfo/<int:oltid>/<string:onu>')
@login_required
def onuconfinfo(oltid, onu):
    '''
    Просмотр конфигурации ОНУ
    '''
    userid = current_user.get_id()
    userinfo = g.userbase.get_user(userid)
    try:
        olt_find = FindOlt(userinfo, oltid)
        olt_information = olt_find.oltinfo()
    except ValueError:
        return redirect('/forbidden')
    
    try:
        onurequest = ConnOLT(olt_information, onu, g.CONN)
        conf_onu_info = onurequest.confonuinfo()

    except:
        log_write(f"User: {userinfo['username']}; Action: SHOW_ONU_CONF; Message: Не получилось посмотреть конфигурацию ОНУ {onu}")
        flash({'result': 'error', 'message': 'Ошибка. Не получилось подключиться к ОЛТу по Telnet/SSH'})

        return redirect(f"/onuinfo/{onu}")

    log_write(f"User: {userinfo['username']}; Action: SHOW_ONU_CONF; Message: Просмотр конфигурации ОНУ {onu}")

    return render_template('/onuconfinfo.html', conf_onu_info=conf_onu_info)


@app.route('/oltshowlogs/<int:id>')
@login_required
def oltlogs(id):
    '''
    Просмотр логов ОЛТа
    '''
    userid = current_user.get_id()
    userinfo = g.userbase.get_user(userid)
    try:
        olt_find = FindOlt(userinfo, id) 
        olt_information = olt_find.oltinfo()
    except ValueError:
        return redirect('/forbidden')
    
    try:
        logsrequest = ShowLogs(olt_information, g.CONN)
        logs_info = logsrequest.showlogs()
    except:
        log_write(f"User: {userinfo['username']}; \
                Action: SHOWLOGS; Message: Ошибка. \
                Не получилось подключиться к ОЛТу {olt_information['ip_address']} по Telnet/SSH")
        flash({'result': 'error', 'message': 'Ошибка. Не получилось подключиться к ОЛТу по Telnet/SSH'})

        return redirect(f"/oltinfo/{id}")

    log_write(f"User: {userinfo['username']}; Action: SHOWLOGS; Message: Просмотр логов ОЛТа {olt_information['ip_address']}")

    return render_template('/oltshowlogs.html', logs_info=logs_info)


@app.route('/saveconfig/<int:oltid>')
@login_required
def save_config(oltid):
    '''
    Сохранить конфигурацию ОЛТа
    '''
    userid = current_user.get_id()
    userinfo = g.userbase.get_user(userid)
    try:
        olt_find = FindOlt(userinfo, oltid)
    except ValueError:
        return redirect('/forbidden')

    result = olt_find.save_config()
    
    log_write(f"User: {userinfo['username']}; Action: SAVE_CONFIG; Message: {result['message']}")
    flash(result)
    
    return redirect(f'/oltinfo/{oltid}')
    

if __name__ == "__main__":
    app.run(debug=DEBUG, host=IP_SRV, port=PORT_SRV)
