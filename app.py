from flask import Flask, render_template, url_for, request, redirect, flash
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import ipaddress
import os

from onumonitoring.oltinfo import OltInfo
from onumonitoring.findonu import FindOnu
from onumonitoring.get_olts import get_netbox_olt_list, olts_update, update_olt, delete_olt
from onumonitoring.work_db import WorkDB

from dotenv import load_dotenv


load_dotenv()

# Имя базы и путь до неё, папка должна быть instance, иначе не будет работать
NAMEDB = "onulist.db"
PATHDB = f"instance/{NAMEDB}"

IP_SRV = os.getenv('IP_SRV')
PORT_SRV = os.getenv('PORT_SRV')

SNMP_READ_H = os.getenv('SNMP_READ_H')
SNMP_READ_B = os.getenv('SNMP_READ_B')
SNMP_CONF_H = os.getenv('SNMP_CONF_H')
SNMP_CONF_B = os.getenv('SNMP_CONF_B')
PF_HUAWEI = os.getenv('PF_HUAWEI')
PF_BDCOM = os.getenv('PF_BDCOM')
DEBUG = os.getenv('DEBUG')

load_dotenv()
# NetBox
TOKEN_API = os.getenv('API_KEY')
HEADERS = {"Authorization": TOKEN_API}

# Имя базы и путь до неё, папка должна быть instance, иначе не будет работать
NAMEDB = "onulist.db"
PATHDB = f"instance/{NAMEDB}"

IP_SRV = os.getenv('IP_SRV')
PORT_SRV = os.getenv('PORT_SRV')

SNMP_READ_H = os.getenv('SNMP_READ_H')
SNMP_READ_B = os.getenv('SNMP_READ_B')
SNMP_CONF_H = os.getenv('SNMP_CONF_H')
SNMP_CONF_B = os.getenv('SNMP_CONF_B')
PF_HUAWEI = os.getenv('PF_HUAWEI')
PF_BDCOM = os.getenv('PF_BDCOM')

app = Flask(__name__)
api = Api()
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{NAMEDB}'
app.config['SECRET_KEY'] = 'asf09u23rpqdm0123r'

db = SQLAlchemy(app)


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
        onurequest = FindOnu(onu, PATHDB)
        onu_info = onurequest.onuinfo()

        return onu_info


api.add_resource(Main_Api, "/api/onuinfo/<string:onu>")
api.init_app(app)


@app.route("/", methods=['POST', 'GET'])
def index():
    ''' Главная страница, получение через строку поиска мака или серийника ОНУ
    и дальнейшая обработка'''

    if request.method == "POST":
        try:
            searchonu = request.form['searchonu']
            onu = searchonu.lower().replace(' ','').replace(':', '').replace('.', '').replace('hwtc', '48575443').replace('-', '')
            if len(onu) == 12:
            
                onurequest = FindOnu(onu, PATHDB)
                onu_info = onurequest.onuinfo()
                return render_template("/onuinfo.html", onu_info=onu_info)

            elif len(onu) == 16:
            
                onurequest = FindOnu(onu, PATHDB)
                onu_info = onurequest.onuinfo()

                return render_template("/onuinfo.html", onu_info=onu_info)
           
            else:
                onu = f"Неправильный мак или серийный номер: {onu}"
                return render_template("/onunotfound.html", onu=onu)

        except AttributeError:
            onu = f"Ону {onu} не найдена"
            return render_template("/onunotfound.html", onu=onu)

    else:        
        olts_list = OLTs.query.all()
        return render_template("index.html", olts_list=olts_list)

        
@app.route("/help")
def help_page():
    ''' Страница справки '''
    return render_template("help.html")


@app.route('/onuinfo/<string:onu>')
def onuinfo(onu):
    '''
    Тестовая функция вывода инфы об ОНУ
    '''
    onurequest = FindOnu(onu, PATHDB)
    onu_info = onurequest.onuinfo()

    return render_template('/onuinfo.html', onu_info=onu_info)


@app.route("/oltinfo/<int:number>")
def olt_info(number):
    ''' Страница просмотра информации об ОЛТе '''
    olts_list = OLTs.query.get(number)
    port_list = AboutOlt.query.all()
   
    ports = []
    if PF_HUAWEI in olts_list.platform:
        for i in port_list:
            if i.ip_address == olts_list.ip_address:
                ports.append(i.ponport)

        oltinfo_params = {
        "pathdb": PATHDB,
        "olt_ip": olts_list.ip_address,
        "olt_port": '',
        "platform": olts_list.platform,
        "pontype": olts_list.pon,
        }
        olt_info = OltInfo(**oltinfo_params)
        unregonu = olt_info.hwunregonu()

    if PF_BDCOM in olts_list.platform:
        unregonu = []
        for i in port_list:
            if i.ip_address == olts_list.ip_address:
                if ":" in i.ponport:
                    pass
                else:
                    ports.append(i.ponport)

    ports.sort()

    return render_template("oltinfo.html", olts_list=olts_list, ports=ports, unregonu=unregonu)


@app.route("/oltinfo/<int:number>/<string:port>")
def olt_port_info(number, port):
    ''' Страница просмотра дерева '''
    
    olts_list = OLTs.query.get(number)
    olt_port = port.replace(".", "/")
    try:
        if PF_HUAWEI in olts_list.platform:
            olt_info = OltInfo(PATHDB, olts_list.ip_address, olt_port, olts_list.platform, olts_list.pon) 
            out_tree = olt_info.hwponstatustree()

        elif PF_BDCOM in olts_list.platform:
            olt_info = OltInfo(PATHDB, olts_list.ip_address, olt_port, olts_list.platform, olts_list.pon)
            out_tree = olt_info.bdcomponstatustree()

        return render_template("oltportinfo.html", out_tree=out_tree, olt_port=olt_port, oltip=olts_list.ip_address, hostname=olts_list.hostname)

    except KeyError:
        flash("База устарела, опросите ОЛТ")

        return redirect(f"/oltinfo/{number}")


@app.route("/oltinfo/<int:number>/update")
def olt_update(number):
    ''' Опрос конкретного ОЛТа '''
#    try:
    update_olt(PATHDB, number)
    flash("ОЛТ опрошен")
    
    return redirect(f'/')


@app.route("/oltslistupdate")
def oltslistupdate():
    ''' Получить список ОЛТов из НетБокса '''
    try:
        get_netbox_olt_list()
        flash('Получен список ОЛТов из NetBox')

        return redirect('/')

    except:
        flash('ERROR. Убедитесь, что на всех ОЛТах проставлены теги и платформы')


@app.route("/oltsupdate")
def oltsupdate():
    ''' Опросить ВСЕ ОЛТы '''
#    try:
    olts_update(PATHDB)
    flash('Опрос ОЛТов завершён')
#    flash("Функция отключена Администратором")

    return redirect('/')
   

@app.route("/doubleonu")
def doubleonu():
    ''' Поиск дубликатов ОНУ '''
#    try:
    db = WorkDB(PATHDB)
    maconu = db.finddoublemac();
    snonu = db.finddoublesn();

    return render_template('/doubleonu.html', maconu=maconu, snonu=snonu)


@app.errorhandler(404)
def pagenotfound(error):
    ''' Страница 404 '''
    return render_template('page404.html', title="Страница не найдена")


@app.route("/onuinfo/<string:onu>/catvon")
def onu_catvon(onu):
    ''' Включить CATV порт '''
    onurequest = FindOnu(onu, PATHDB)
    out = onurequest.onucatvon()

    return redirect(f'/onuinfo/{onu}')


@app.route("/onuinfo/<string:onu>/catvoff")
def onu_catvoff(onu):
    ''' Выключить CATV порт '''
    onurequest = FindOnu(onu, PATHDB)
    out = onurequest.onucatvoff()
            
    return redirect(f'/onuinfo/{onu}')


@app.route("/oltadd", methods=['POST', 'GET'])
def olt_add():
    ''' Добавление нового ОЛТа (Если нет НетБокса) '''
#    olt_add = OLTs.query.get(number)
    if request.method == "POST":
        hostname = request.form['hostname']
        oltip = request.form['ip_address']
        platform = request.form['platform']
        pontype = request.form['pontype']
   
        try:
            ipv4 = ipaddress.ip_address(oltip)

            if "Выберите" in platform or "Выберите" in pontype:
                flash("Не выбрана платформа или тип портов")

                return render_template("oltadd.html", pf_huawei=PF_HUAWEI, pf_bdcom=PF_BDCOM)

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

            return render_template("oltadd.html", pf_huawei=PF_HUAWEI, pf_bdcom=PF_BDCOM)

    else:

        return render_template("oltadd.html", pf_huawei=PF_HUAWEI, pf_bdcom=PF_BDCOM)


@app.route("/oltinfo/<int:number>/delete")
def olt_delete(number):
    ''' Удаление ОЛТа (Если нет НетБокса) '''
#    olt_del = OLTs.query.get(number)
    delete_olt(PATHDB, number)
    flash("ОЛТ удалён из базы")

    return redirect("/")


@app.route("/onuinfo/<string:onu>/reboot")
def onu_reboot(onu):    
    ''' 
    Перезагрузка ОНУ
    '''
    onurequest = FindOnu(onu, PATHDB)
    out = onurequest.onureboot()
    flash(out)
                
    return redirect(f'/onuinfo/{onu}')


@app.route("/onuinfo/<string:onu>/deleteonu")
def onu_delete(onu):    
    ''' 
    Удалить ОНУ с ОЛТа
    '''
#    onurequest = FindOnu(onu, PATHDB)
#    out = onurequest.onureboot()
#    flash(out)
    flash('Ошибка. Функция в разработке')
                
    return redirect(f'/onuinfo/{onu}')


@app.route('/settings')
def olthub_settings():
    return render_template('/settings.html')


if __name__ == "__main__":
    app.run(debug=DEBUG, host=IP_SRV, port=PORT_SRV)
