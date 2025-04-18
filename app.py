from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import ipaddress

from onumonitoring.oltinfo import OltInfo
from onumonitoring.findonu import FindOnu
from onumonitoring.get_olts import get_netbox_olt_list, olts_update, update_olt, delete_olt
from onumonitoring.work_db import WorkDB
from config import SNMP_READ_H, PATHDB, SNMP_READ_B, NETBOX, SNMP_CONF_H, NAMEDB, IP_SRV, PORT_SRV, PF_HUAWEI, PF_BDCOM


app = Flask(__name__)
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


@app.route("/", methods=['POST', 'GET'])
def index():
    ''' Главная страница, получение через строку поиска мака или серийника ОНУ
    и дальнейшая обработка'''

    if request.method == "POST":
        try:
            searchonu = request.form['searchonu']
            onu = searchonu.lower().replace(' ','').replace(':', '').replace('.', '').replace('hwtc', '48575443').replace('-', '')
            if len(onu) == 12:
            
                onurequest = FindOnu(onu, "epon", PATHDB)
                out = onurequest.surveyonu()

                return render_template("/onuinfo.html", out=out, onu=onu)

            elif len(onu) == 16:
            
                onurequest = FindOnu(onu, "gpon", PATHDB)
                out = onurequest.surveyonu()

                return render_template("/onuinfo.html", out=out, onu=onu)
           
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


@app.route("/onuinfo/<string:onu>")
def onu_info(onu):
    ''' Страница информации об ОНУ '''
    try:
        onu = onu.lower().replace(' ','').replace(':', '').replace('.', '').replace('hwtc', '48575443').replace('-', '')
        if len(onu) == 12:

            onurequest = FindOnu(onu, "epon", PATHDB)
            out = onurequest.surveyonu()

            return render_template("/onuinfo.html", out=out, onu=onu)


        elif len(onu) == 16:

            onurequest = FindOnu(onu, "gpon", PATHDB)
            out = onurequest.surveyonu()

            return render_template("/onuinfo.html", out=out, onu=onu)

        else:
            onu = f"Неправильный мак или серийный номер: {onu}"
            return render_template("/onunotfound.html", onu=onu)

    except AttributeError:
        onu = f"Ону {onu} не найдена"
        return render_template("/onunotfound.html", onu=onu)


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

    if PF_BDCOM in olts_list.platform:
        for i in port_list:
            if i.ip_address == olts_list.ip_address:
                if ":" in i.ponport:
                    pass
                else:
                    ports.append(i.ponport)

    ports.sort()

    return render_template("oltinfo.html", olts_list=olts_list, ports=ports, nb=NETBOX)


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


@app.route("/leveltree/<string:onu>")
def level_tree(onu):
    ''' Страница информации о дереве '''
    if len(onu) == 12:
        out = ['Ошибка']
        outstate = ['Ошибка']
        onurequest = FindOnu(onu, "epon", PATHDB)
        out = onurequest.surveytreelevel()
        outstate = onurequest.surveytree()

        return render_template("/leveltree.html", out=out, outstate=outstate)

    elif len(onu) == 16:

        onurequest = FindOnu(onu, "gpon", PATHDB)
        out = onurequest.surveytreelevel()
        outstate = onurequest.surveytree()

        return render_template("/leveltree.html", out=out, outstate=outstate)


    else:
        return render_template("index.html")


@app.route("/oltinfo/<int:number>/update")
def olt_update(number):
    ''' Опрос конкретного ОЛТа '''
#    try:
    update_olt(PATHDB, number)
    flash("ОЛТ опрошен")
    
    return redirect("/")

#    except sqlite3.OperationalError: 
#        return render_template("oltupdateerror.html")


@app.route("/oltslistupdate")
def oltslistupdate():
    ''' Получить список ОЛТов из НетБокса '''
    if NETBOX == "1":
        try:
            get_netbox_olt_list()
            flash('Получен список ОЛТов из NetBox')
#            flash("Функция отключена Администратором")

            return redirect('/')

        except:
            flash('ERROR. Убедитесь, что на всех ОЛТах проставлены теги и платформы')

            return redirect('/')

    elif NETBOX == "2":
#        flash("NetBox отключён, ОЛТы добавляются в ручном режиме")
        
        return redirect('/oltadd')

    else:
        flash("ERROR")

        return redirect('/')


@app.route("/oltsupdate")
def oltsupdate():
    ''' Опросить ВСЕ ОЛТы '''
#    try:
    olts_update(PATHDB)
    flash('Опрос ОЛТов завершён')
#    flash("Функция отключена Администратором")

    return redirect('/')
   
#    except sqlite3.OperationalError:
#        return render_template("oltupdateerror.html")


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
    onurequest = FindOnu(onu, "gpon", PATHDB)
    out = onurequest.onucatvon()

    return redirect(f'/onuinfo/{onu}')


@app.route("/onuinfo/<string:onu>/catvoff")
def onu_catvoff(onu):
    ''' Выключить CATV порт '''
    onurequest = FindOnu(onu, "gpon", PATHDB)
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


if __name__ == "__main__":
    app.run(debug=True, host=IP_SRV, port=PORT_SRV)
