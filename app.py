from flask import Flask, render_template, url_for, request, redirect, flash
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import ipaddress
import os

from cl_int.findonu import FindOnu
from cl_int.actonu import ActionOnu
from cl_other.get_olts import get_netbox_olt_list, olts_update, update_olt, delete_olt
from cl_db.work_db import WorkDB
from cl_int.findolt import FindOlt
from cl_db.db_cfg import Init_Cfg
from cl_db.db_menucfg import InitMenuCfg
from cl_db.db_users import Users_Cfg, UserInfo
from cl_db.userlogin import UserLogin
from werkzeug.security import generate_password_hash, check_password_hash

from dotenv import load_dotenv


load_dotenv()

# Имя базы и путь до неё, папка должна быть instance, иначе не будет работать
NAMEDB = "onulist.db"
PATHDB = f"instance/{NAMEDB}"

IP_SRV = os.getenv('IP_SRV')
PORT_SRV = os.getenv('PORT_SRV')
DEBUG = os.getenv('DEBUG')

app = Flask(__name__)
api = Api()
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{NAMEDB}'
app.config['SECRET_KEY'] = 'asf09u23rpqdm0123r'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Авторизуйтесь для доступа к сайту'


@login_manager.user_loader
def load_user(user_id):
    return UserLogin().User_Cfg


class OLTs(db.Model):
    __tablename__ = 'olts'
    number = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.Text)
    ip_address = db.Column(db.Text)
    platform = db.Column(db.Text)
    pon = db.Column(db.Text)
    
    def __repr__(self):
        return '<OLTs %r>' % self.number


class AboutOlt(db.Model):
    __tablename__ = 'ponports'
    number = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.Text)
    ip_address = db.Column(db.Text)
    ponport = db.Column(db.Text)
    portoid = db.Column(db.Text)
    
    def __repr__(self):
        return '<AboutOlt %r>' % self.number


class Main_Api(Resource):
    def get(self, onu):
        if current_user.is_authenticated:
            onurequest = FindOnu(onu, PATHDB)
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
    dbase = UserInfo(PATHDB)
    menucfg = InitMenuCfg(PATHDB)


@login_manager.user_loader
def load_user(user_id):
    return UserLogin().fromDB(user_id, dbase)


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
        user = dbase.getUserByName(request.form['username'])
        if user and check_password_hash(user['psw'], request.form['psw']):
            userlogin = UserLogin().create(user)
            rm = True if request.form.get('remember-me') else False
            login_user(userlogin, remember=rm)
            flash('Успешный вход в систему')
            return redirect(request.args.get('next') or '/')
        else:
            flash('Неправильный логин/пароль')
            return redirect('/login')
    else:    
        return render_template('/login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из аккаунта')
    return redirect('/login')


@app.route('/settings/profile', methods=['POST', 'GET'])
@login_required
def profile():
    '''
    Профиль пользователя
    '''
    userid = current_user.get_id()
    user_profile = UserInfo(PATHDB).getUser(userid)
    if request.method == 'POST':
        if request.form['psw'] == request.form['psw_repeat']:
            change_psw = Users_Cfg(PATHDB)
            out = change_psw.changepsw(userid, request.form['psw'])
            flash(out)
            return redirect('/settings/profile')
        else:
            flash('Ошибка. Пароли не совпадают.')
            return redirect('/settings/profile')
    else:
        menu = menucfg.getmenucfg(user_profile['privilage'])
        return render_template('/settings_profile.html', user_profile=user_profile, menu=menu)


@app.route("/", methods=['POST', 'GET'])
@login_required
def index():
    ''' 
    Главная страница, получение через строку поиска мака или серийника ОНУ
    и дальнейшая обработка
    '''
    if request.method == "POST":
        try:
            onu = request.form['searchonu']
            onurequest = FindOnu(onu, PATHDB)
            onu_info = onurequest.onuinfo()

            return render_template("/onuinfo.html", onu_info=onu_info)
           
        except TypeError:
            onu = f"Неправильный мак или серийный номер: {onu}"
            return render_template("/onunotfound.html", onu=onu)

        except ValueError:
            onu = f"Ону {onu} не найдена"
            return render_template("/onunotfound.html", onu=onu)

    else:
        try:
            olts_list = OLTs.query.all()
            return render_template("index.html", olts_list=olts_list)

        except:
            return redirect('/settings/cfgdb')

        
@app.route("/help")
def help_page():
    ''' Страница справки '''
    return render_template("help.html")


@app.route('/onuinfo/<string:onu>')
@login_required
def onuinfo(onu):
    '''
    Информация об ОНУ 
    '''
    onurequest = FindOnu(onu, PATHDB)
    onu_info = onurequest.onuinfo()
    return render_template('/onuinfo.html', onu_info=onu_info)


@app.route("/oltinfo/<int:number>")
@login_required
def olt_info(number):
    ''' 
    Страница просмотра информации об ОЛТе
    '''
    olts_list = OLTs.query.get(number)
    port_list = AboutOlt.query.all()
    
    olt_params = {
    "pathdb": PATHDB,
    "olt_id": number,
    }   

    olt_find = FindOlt(**olt_params) 
    olt_information = olt_find.oltinfo()

    return render_template("oltinfo.html", olt_information=olt_information)


@app.route("/oltinfo/<int:number>/<string:port>")
@login_required
def olt_port_info(number, port):
    '''
    Страница просмотра дерева
    '''
    olt_port = port.replace(".", "/")
    try:
        olt_information = FindOlt(PATHDB, number, olt_port)
        o_info = olt_information.oltinfo()
        pon_status = olt_information.ponportstatus()
        return render_template("oltportinfo.html", pon_status=pon_status, olt_port=olt_port, oltip=o_info['ip_address'], hostname=o_info['oltname'])

    except KeyError:
        flash("База устарела, опросите ОЛТ")
        return redirect(f"/oltinfo/{number}")


@app.route("/oltinfo/<int:number>/update")
@login_required
def olt_update(number):
    ''' 
    Опрос конкретного ОЛТа
    '''
    update_olt(PATHDB, number)
    flash("ОЛТ опрошен")
    return redirect(f'/oltinfo/{number}')


@app.route("/oltupdate/<int:number>")
@login_required
def updateolt(number):
    ''' 
    Опрос конкретного ОЛТа с главной страницы
    '''
    update_olt(PATHDB, number)
    flash("ОЛТ опрошен")
    return redirect('/')


@app.route("/oltslistupdate")
@login_required
def oltslistupdate():
    '''
    Получить список ОЛТов из НетБокса
    '''
    try:
        get_netbox_olt_list()
        flash('Получен список ОЛТов из NetBox')
        return redirect('/')

    except:
        flash('Ошибка. Убедитесь, что настройки для NetBox правильные.')
        return redirect('/settings/cfgnb')


@app.route("/oltsupdate")
@login_required
def oltsupdate():
    '''
    Опросить ВСЕ ОЛТы
    '''
    olts_update(PATHDB)
    flash('Опрос ОЛТов завершён')
    return redirect('/')
   

@app.route("/doubleonu")
@login_required
def doubleonu():
    '''
    Поиск дубликатов ОНУ
    '''
    db = WorkDB(PATHDB)
    maconu = db.finddoublemac();
    snonu = db.finddoublesn();
    return render_template('/doubleonu.html', maconu=maconu, snonu=snonu)


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
    onurequest = ActionOnu(PATHDB, onu, oltid)
    out = onurequest.onucatvon()
    return redirect(f'/onuinfo/{onu}')


@app.route("/onuinfo/<int:oltid>/<string:onu>/catvoff")
@login_required
def onu_catvoff(oltid, onu):
    '''
    Выключить CATV порт
    '''
    onurequest = ActionOnu(PATHDB, onu, oltid)
    out = onurequest.onucatvoff()        
    return redirect(f'/onuinfo/{onu}')


@app.route("/settings/oltadd", methods=['POST', 'GET'])
@login_required
def olt_add():
    '''
    Добавление нового ОЛТа (Если нет НетБокса) 
    '''
    userid = current_user.get_id()
    userinfo = UserInfo(PATHDB).getUser(userid)
    if userinfo['privilage'] == 'Administrator':
        getcfg = Init_Cfg(PATHDB)
        cfg = getcfg.getcfg()
        PF_HUAWEI = cfg['PL_H']
        PF_BDCOM = cfg['PL_B']
        menu = menucfg.getmenucfg(userinfo['privilage'])
        if request.method == "POST":
            hostname = request.form['hostname']
            oltip = request.form['ip_address']
            platform = request.form['platform']
            pontype = request.form['pontype']
       
            try:
                ipv4 = ipaddress.ip_address(oltip)

                if "Выберите" in platform or "Выберите" in pontype:
                    flash("Не выбрана платформа или тип портов")

                    return render_template("oltadd.html", pf_huawei=PF_HUAWEI, pf_bdcom=PF_BDCOM, menu=menu)

                else:
                    oltadd = OLTs(hostname=hostname, ip_address=oltip, platform=platform, pon=pontype)

                    try:
                        db.session.add(oltadd)
                        db.session.commit()
                        flash("OLT добавлен в базу")

                        return redirect('/')
            
                    except:
                        return "При добавлении ОЛТа произошла ошибка"

            except:
                flash("Некорректный IP адресс")

                return render_template("oltadd.html", pf_huawei=PF_HUAWEI, pf_bdcom=PF_BDCOM, menu=menu)

        else:
            return render_template("oltadd.html", pf_huawei=PF_HUAWEI, pf_bdcom=PF_BDCOM, menu=menu)

    else:
        return redirect('forbidden')


@app.route("/oltinfo/<int:number>/delete")
@login_required
def olt_delete(number):
    '''
    Удаление ОЛТа (Если нет НетБокса)
    '''
    userid = current_user.get_id()
    userinfo = UserInfo(PATHDB).getUser(userid)
    if userinfo['privilage'] == 'Administrator':    
        delete_olt(PATHDB, number)
        flash("ОЛТ удалён из базы")

        return redirect("/")
    else:
        flash('Ошибка! У вас недостаточно прав для удаления ОЛТа.')
        return redirect(f'/oltinfo/{number}')


@app.route("/onuinfo/<int:oltid>/<string:onu>/reboot")
@login_required
def onu_reboot(oltid, onu):    
    ''' 
    Перезагрузка ОНУ
    '''
    onurequest = ActionOnu(PATHDB, onu, oltid)
    out = onurequest.onureboot()
    flash(out)
                
    return redirect(f'/onuinfo/{onu}')


@app.route("/onuinfo/<int:oltid>/<string:onu>/deleteonu")
@login_required
def onu_delete(oltid, onu):    
    ''' 
    Удалить ОНУ с ОЛТа
    '''
    onurequest = ActionOnu(PATHDB, onu, oltid)
    out = onurequest.onudelete()
    flash(out)
                
    return redirect(f'/onuinfo/{onu}')


@app.route('/settings/cfgsnmp', methods=['POST', 'GET'])
@login_required
def olthub_settings_snmp():
    '''
    Конфигурация SNMP
    '''
    userid = current_user.get_id()
    userinfo = UserInfo(PATHDB).getUser(userid)
    if userinfo['privilage'] == 'Administrator':
        if request.method == "POST":
            snmp_cfg = {
                'snmp_read_h': request.form['snmp_read_h'],
                'snmp_conf_h': request.form['snmp_conf_h'],
                'snmp_read_b': request.form['snmp_read_b'],
                'snmp_conf_b': request.form['snmp_conf_b'],
            }
            setsnmpcfg = Init_Cfg(PATHDB)
            out = setsnmpcfg.insercfgsnmp(**snmp_cfg)
            flash(out)
            return redirect('/settings/cfgsnmp')
        else:
            menu = menucfg.getmenucfg(userinfo['privilage'])
            nbcfg = Init_Cfg(PATHDB)
            cfg = nbcfg.getcfg()
            return render_template('/settings_snmp.html', cfg=cfg, menu=menu)
    else:   
        return redirect('/forbidden')


@app.route('/settings/cfgnb', methods=['POST', 'GET'])
@login_required
def olthub_settings_nb():
    '''
    Конфигурация NetBox
    '''
    userid = current_user.get_id()
    userinfo = UserInfo(PATHDB).getUser(userid)
    if userinfo['privilage'] == 'Administrator':
        if request.method == "POST":
            nb_cfg = {
                'api_key': request.form['api_key'],
                'epon_tag': request.form['tag_epon'],
                'gpon_tag': request.form['tag_gpon'],
                'urlnb': request.form['urlnb'],
                'pl_h': request.form['pl_h'],
                'pl_b': request.form['pl_b'],
            }
            setnbcfg = Init_Cfg(PATHDB)
            out = setnbcfg.insertcfgnb(**nb_cfg)
            flash(out)
            return redirect('/settings/cfgnb')
        else:
            menu = menucfg.getmenucfg(userinfo['privilage'])
            nbcfg = Init_Cfg(PATHDB)
            cfg = nbcfg.getcfg()
            key = cfg['API_KEY']
            cfg['API_KEY'] = 15*'*' + key[-5:]
            return render_template('/settings_nb.html', cfg=cfg, menu=menu)
    else:
        return redirect('/forbidden')


@app.route('/settings/adduser', methods=['POST', 'GET'])
@login_required
def olthub_adduser():
    '''
    Добавить пользователя
    '''
    userid = current_user.get_id()
    userinfo = UserInfo(PATHDB).getUser(userid)
    if userinfo['privilage'] == 'Administrator':
        if request.method == "POST":
            username = request.form['username']
            psw = request.form['psw']
            privilage = request.form['privilage']
            add_user = Users_Cfg(PATHDB)
            user_out = add_user.adduser(username, psw, privilage)
            flash(user_out)
            return redirect('/settings/adduser')
        else:
            menu = menucfg.getmenucfg(userinfo['privilage'])
            getusers = Users_Cfg(PATHDB)
            users = getusers.getusers()
            return render_template('/settings_users.html', users=users, menu=menu)
    else:
        return redirect('/forbidden')


@app.route('/settings/deluser/<string:username>')
@login_required
def olthub_deluser(username):
    '''
    Удалить пользователя
    '''
    userid = current_user.get_id()
    userinfo = UserInfo(PATHDB).getUser(userid)
    if userinfo['privilage'] == 'Administrator':
        deluser = Users_Cfg(PATHDB)
        deluser.deluser(username)
        flash('Пользователь удалён')
        return redirect('/settings/adduser')
    else:
        return redirect('/forbidden')


if __name__ == "__main__":
    app.run(debug=DEBUG, host=IP_SRV, port=PORT_SRV)
