# -*- coding: utf-8 -*-

from flask import Flask, jsonify, render_template, url_for, request, session, redirect
from flask_mongoengine import MongoEngine
from datetime import datetime
import re, hashlib, time, string
from translate import translations
from myrandom import getRandomString

EXPERTIME = 7*24*3600 # ONE WEEK

app = Flask(__name__)

app.secret_key = b'&\xc2\x94\x83\t\xd4LF\x00H&\x8c\x03\x92\xec{\xedP0\x95\x9e9\xc7\x0c'

app.config['MONGODB_SETTINGS'] = {
    'db': 'flask',
    'host': 'localhost',
    'port': 27017,
    'username': 'nvEjiegI24',
    'password': 'kojdisaJIEHF$%4%$'
}

mdb = MongoEngine()
mdb.init_app(app)

languages = ["en", "zhCN", "zhTW", "es"]


@app.template_global()
def tr(string):
    if "lang" in session and session["lang"] in languages:
        lang = session["lang"]
    else:
        session['lang'] = "zhCN"
        lang = "zhCN"
    return translations[lang][string]


@app.template_global()
def getLang():
    if "lang" in session and session["lang"] in languages:
        lang = session["lang"]
    else:
        session['lang'] = "zhCN"
        lang = "zhCN"
    return lang


class TypeData(mdb.Document):
    meta = {
        'collection': 'types',
        'ordering': ['-create_at'],
        'strict': False,
    }
    mtype = mdb.StringField()
    name = mdb.StringField()
    create_at = mdb.DateTimeField(default=datetime.now)


typelist = []

for mtype in TypeData.objects():
    typelist.append([mtype.mtype, mtype.name])


class SecureCodesData(mdb.Document):
    meta = {
        'collection': 'securecodes',
        'ordering': ['-create_at'],
        'strict': False,
    }
    mlevel = mdb.IntField(default=0)
    msecure = mdb.StringField()
    used = mdb.BooleanField(default=True)
    create_at = mdb.DateTimeField(default=datetime.now)


def checkSecureCodes(code, level):
    codes = SecureCodesData.objects(msecure=code, used=False)
    if codes:
        if level <= codes[0].mlevel:
            codes[0].update(used=True)
            return True
    return False

def createSecureCode(level):
    code = getRandomString(12)
    while len(SecureCodesData.objects(msecure=code)) > 0:
        code = getRandomString(12)
    SecureCodesData(mlevel=level, msecure=code, used=False).save()
    return code


class UserData(mdb.Document):
    meta = {
        'collection': 'users',
        'ordering': ['-create_at'],
        'strict': False,
    }
    user = mdb.StringField()
    showname = mdb.StringField()
    passwordMd5 = mdb.StringField()
    create_at = mdb.DateTimeField(default=datetime.now)
    readAvailable = mdb.BooleanField(default=True)
    writeAvailable = mdb.BooleanField(default=False) # for level 1 and above
    controlArticlesAvailable = mdb.BooleanField(default=False) # for level 2 and above
    controlUsersAvailable = mdb.BooleanField(default=False) # for level 3 and above
    controlClassesAvailable = mdb.BooleanField(default=False) # for level 4 and above
    controlAdminAvailable = mdb.BooleanField(default=False) # for level 10(top)
    lastAuthChange = mdb.FloatField(defalut=0.0)
    controlLevel = mdb.IntField(default=0)
    likeTopics = mdb.ListField(default=[])


class InfoData(mdb.Document):
    meta = {
        'collection': 'infos',
        'ordering': ['-create_at'],
        'strict': False,
    }
    user = mdb.StringField()
    type = mdb.StringField(default="")
    title = mdb.StringField()
    passage = mdb.StringField(default="RT")
    # target_time = mdb.DateTimeField()
    create_at = mdb.DateTimeField(default=datetime.now)


def getToken(user, time):
    return hashlib.md5((user+str(time)).encode('utf-8')).hexdigest()

def checkToken(user, time, mtoken):
    return mtoken==getToken(user, time)

def md5Pwd(password):
    return hashlib.md5(password.encode('utf-8')).hexdigest()

def checkGoodPassword(password):
    # 之后再写吧
    return not bool(re.match(re.compile(r'[ ()\\]+'), password)) and len(password) >= 6 and len(password) <= 16

def findUser(user):
    return bool(len(UserData.objects(user=user)))

def checkUser(user):
    return bool(re.match(re.compile(r'^[a-z0-9A-Z_]+$'), user)) and len(user) >= 4 and len(user) <= 16

def checkNewUser(user):
    return checkUser(user) and not findUser(user)

def checkUserPass(user, md5pass):
    return bool(len(UserData.objects(user=user, passwordMd5=md5pass)))

def getuserInfo(user):
    return UserData.objects(user=user)

def getuserWritable(user):
    return findUser(user) and getuserInfo(user)[0].writeAvailable

def getuserReadable(user):
    return findUser(user) and getuserInfo(user)[0].readAvailable

def getuserControlAdminAvailable(user):
    return findUser(user) and getuserInfo(user)[0].controlAdminAvailable

def checkuserAuthTime(user, sessionTime):
    return findUser(user) and getuserInfo(user)[0].lastAuthChange < sessionTime

def controlClassesAvailable(user):
    return findUser(user) and getuserInfo(user)[0].controlClassesAvailable

def controlArticlesAvailable(user):
    return findUser(user) and getuserInfo(user)[0].controlArticlesAvailable

def controlUsersAvailable(user):
    return findUser(user) and getuserInfo(user)[0].controlUsersAvailable

def loggedinCheck():
    ans = 'username' in session and 'create-time' in session and isinstance(session['create-time'], float) and \
          session['create-time'] < time.time() and time.time() - session['create-time'] < EXPERTIME and \
          checkToken(session['username'], session['create-time'], session['mtoken']) and \
          checkuserAuthTime(session['username'], session['create-time'])
    if ans:
        session['create-time'] = time.time()
        session['mtoken'] = getToken(session['username'], session['create-time'])
    else:
        forceLogout()
    return ans

def calControlLevel(secure, rootSign=False, level2=False, level3=False, level4=False):
    if secure:
        if rootSign:
            return 10
        if level4:
            return 4
        if level3:
            return 3
        if level2:
            return 2
        return 1
    return 0

def getShowName(user):
    if UserData.objects(user=user):
        return UserData.objects(user=user)[0].showname
    return tr("NoneUser")

def getShowType(type):
    ans = tr("classesWrongT")
    for mtype in typelist:
        if mtype[0]==type:
            ans = mtype[1]
            break
    return ans

def shortenPassage(p):
    if len(p) > 30:
        return p[0:27] + "..."
    return p

def shortenTitle(t):
    if len(t) > 20:
        return t[0:17] + "..."
    return t


indexFile = 'index.html'
indexloggedFile = 'index_logged.html'
signFile = 'sign_up.html'
logFile = 'log_in.html'
logoutFile = 'logout.html'
publishFile = 'publish.html'
publishedFile = 'published.html'
errorFile = 'error.html'
error401File = 'error401.html'
securecodeFile = 'securecode.html'
controltypesFile = 'controltypes.html'
controlarticlesFile = 'controlarticles.html'
controlnormalusersFile = 'controlusers.html'

signPath = '/sign_up'
secureSignPath = '/ssign_up'
rootSignPath = "/rsign_up"
level2SignPath = '/s2sign_up'
level3SignPath = '/s3sign_up'
level4SignPath = '/s4sign_up'
logPath = '/log_in'
logoutPath = '/log_out'
checkUserPath = '/checkUser'
publishPath = '/publish'
publishedPath = '/published'
changeLangPath = '/change_lang'
securecodePath = '/securecode'
controltypesPath = '/controltypes'
controlarticlesPath = '/articlelist'
controlnormalusersPath = '/userlist'


def forceLogout():
    session.pop('username', None)
    session.pop('create-time', None)


@app.errorhandler(404)
def pageNotFound(error="404"):
    return render_template(errorFile, homeShow=True, error=error), 404


@app.errorhandler(401)
def pageNotAllowed(error="401"):
    return render_template(error401File, homeShow=True, error=error), 401


@app.route('/', methods=['GET'])
def index():
    infodata = []
    if loggedinCheck():
        info = tr("loggedinIndexInfo1") + str(getShowName(session['username'])) + '（' + session['username'] + '）' + tr("loggedinIndexInfo2")
        logged = logoutShow = True
        signShow = loginShow = False
        publishShow = getuserWritable(session['username'])
        securecodeShow = getuserControlAdminAvailable(session['username'])
        controlTypesShow = controlClassesAvailable(session['username'])
        controlarticlesShow = controlArticlesAvailable(session['username'])
        controlusersShow = controlUsersAvailable(session['username'])
        types = getuserInfo(session['username'])[0].likeTopics
        for i in InfoData.objects():
            if i.type in types:
                infodata.append([getShowType(i.type), getShowName(i.user), shortenTitle(i.title), shortenPassage(i.passage)])
    else:
        info = tr("notloggedinIndexInfo")
        forceLogout()
        securecodeShow = logged = publishShow = logoutShow = controlTypesShow = controlarticlesShow = controlusersShow = \
            False
        signShow = loginShow = True
    return render_template(indexFile, logged=logged, publishShow=publishShow, logoutShow=logoutShow, signShow=signShow,
                           loginShow=loginShow, info=info, infodata=infodata, showthings=(not logged),
                           securecodeShow=securecodeShow, controlTypesShow=controlTypesShow,
                           controlarticlesShow=controlarticlesShow, controlusersShow=controlusersShow)


@app.route(signPath, methods=['GET', 'POST'])
def sign(secure=False, rootSign=False, level2=False, level3=False, level4=False):
    if request.method == 'GET':
        if loggedinCheck():
            return pageNotAllowed(tr("logoutBeforeSignInfo"))
        session['mtoken'] = getToken("", time.time())
        return render_template(signFile, title=tr("signB"), jqueryShow=True, homeShow=True, loginShow=True,
                               typelist=typelist, mtoken=session['mtoken'], secure=secure)
    else:
        if not 'mtoken' in session or not request.form['token'] == session['mtoken'] or loggedinCheck():
            return jsonify(state="ERR", text=tr("errorRefreshInfo"))
        if checkNewUser(request.form['username']):
            if checkGoodPassword(request.form['password']):
                controlLevel = calControlLevel(secure, rootSign=rootSign, level2=level2, level3=level3, level4=level4)
                if not rootSign and controlLevel and not checkSecureCodes(request.form['securecode'], controlLevel):
                    return jsonify(state="ERR", text=tr("securecodeErrorInfo"))
                UserData(user=request.form['username'], passwordMd5=md5Pwd(request.form['password']),
                         writeAvailable=(controlLevel>=1), controlArticlesAvailable=(controlLevel>=2),
                         controlUsersAvailable=(controlLevel>=3), controlClassesAvailable=(controlLevel>=4),
                         controlAdminAvailable=(controlLevel==10), lastAuthChange=time.time(),
                         likeTopics=request.form.getlist('items[]'), showname=request.form['showname'],
                         controlLevel=controlLevel).save()
                session.pop('mtoken', None)
                return jsonify(state="OK", text=tr("signupSucInfo1") + request.form['showname'] +
                                                "（" + request.form['username'] + "）" + tr("signupSucInfo2"))
            else:
                return jsonify(state="ERR", text=tr("passwordErrorInfo"))
        else:
            return jsonify(state="ERR", text=tr("useridErrorInfo"))


@app.route(secureSignPath, methods=['GET', 'POST'])
def ssign():
    return sign(True)


@app.route(rootSignPath, methods=['GET', 'POST'])
def rsign():
    if bool(len(UserData.objects(controlAdminAvailable=True))):
        return redirect(secureSignPath)
    return sign(True, rootSign=True)


@app.route(level2SignPath, methods=['GET', 'POST'])
def s2sign():
    return sign(True, level2=True)


@app.route(level3SignPath, methods=['GET', 'POST'])
def s3sign():
    return sign(True, level3=True)


@app.route(level4SignPath, methods=['GET', 'POST'])
def s4sign():
    return sign(True, level4=True)


@app.route(logPath, methods=['GET', 'POST'])
def log():
    if request.method == 'GET':
        if loggedinCheck():
            return pageNotAllowed(tr("logoutBeforeLoginInfo"))
        session['mtoken'] = getToken("", time.time())
        return render_template(logFile, title=tr("loginB"), jqueryShow=True, homeShow=True, signShow=True,
                               mtoken=session['mtoken'])
    else:
        if not 'mtoken' in session or not request.form['token'] == session['mtoken'] or loggedinCheck():
            return jsonify(state="ERR", text=tr("errorRefreshInfo"))
        if checkUser(request.form['username']) and checkUserPass(request.form['username'],
                                                                 md5Pwd(request.form['password'])):
            session['username'] = request.form['username']
            session['create-time'] = time.time()
            session['mtoken'] = getToken(session['username'], session['create-time'])
            return jsonify(state="OK", text=tr("loggedinIndexInfo1") + str(request.form['username']) + tr("loggedinIndexInfo2"))
        else:
            return jsonify(state="ERR", text=tr("loginfailInfo"))


@app.route(checkUserPath, methods=['POST'])
def checkUserName():
    if checkNewUser(request.form['username']):
        return jsonify(state="OK", text=tr("usernameAvaInfo"))
    else:
        return jsonify(state="ERR", text=tr("usernameNotAvaInfo"))


@app.route(logoutPath, methods=['GET'])
def logoutNow():
    forceLogout()
    return render_template(logoutFile, homeShow=True, signShow=True, loginShow=True)


@app.route(publishPath, methods=['GET', 'POST'])
def publish():
    if request.method == 'GET':
        if not loggedinCheck():
            return pageNotAllowed(tr("loginFirstInfo"))
        if getuserWritable(session['username']):
            session['mtoken'] = getToken(session['username'], session['create-time'])
            return render_template(publishFile, title=tr("publishB"), jqueryShow=True, homeShow=True, typelist=typelist,
                                   mtoken=session['mtoken'], publishShow=True, logoutShow=True,
                                   securecodeShow=getuserControlAdminAvailable(session['username']),
                                   controlTypesShow=controlClassesAvailable(session['username']),
                                   controlarticlesShow=controlArticlesAvailable(session['username']),
                                   controlusersShow=controlUsersAvailable(session['username']))
        else:
            return pageNotAllowed(tr("cannotpublishInfo"))
    else:
        if not 'mtoken' in session or not request.form['token'] == session['mtoken'] or not loggedinCheck():
            return jsonify(state="ERR", text=tr("errorRefreshInfo"))
        InfoData(user=session['username'], title=request.form['title'], passage=request.form['passage'],
                 type=request.form['type']).save()
        return jsonify(state="OK", text=tr("publishSucInfo") + request.form['title'])


@app.route(publishedPath, methods=['GET', 'POST'])
def published():
    if request.method == 'GET':
        if not loggedinCheck():
            return pageNotAllowed(tr("loginFirstInfo"))
        if getuserWritable(session['username']):
            infodata=[]
            for i in InfoData.objects(user=session['username']):
                infodata.append([getShowType(i.type), getShowName(i.user), shortenTitle(i.title), shortenPassage(i.passage), i.id])
            session['mtoken'] = getToken(session['username'], session['create-time'])
            return render_template(publishedFile, title=tr("publishedB"), homeShow=True, infodata=infodata,
                                   mtoken=session['mtoken'], publishShow=True, logoutShow=True,
                                   securecodeShow=getuserControlAdminAvailable(session['username']),
                                   controlTypesShow=controlClassesAvailable(session['username']),
                                   controlarticlesShow=controlArticlesAvailable(session['username']),
                                   controlusersShow=controlUsersAvailable(session['username']))
        else:
            return pageNotAllowed(tr("cannotpublishInfo"))
    else:
        if 'mtoken' in session and request.form['token'] == session['mtoken'] and loggedinCheck() and getuserWritable(session['username']):
            InfoData.objects(id=request.form['chosen']).delete()
        return redirect(publishedPath)


@app.route(changeLangPath, methods=['POST'])
def changeLang():
    session['lang'] = request.form['lang']
    return jsonify(state="OK", text=tr("changedLangInfo"))


@app.route(securecodePath, methods=['GET', 'POST'])
def securecodeNow():
    if request.method == 'GET':
        if not loggedinCheck():
            return pageNotAllowed(tr("loginFirstInfo"))
        if getuserControlAdminAvailable(session['username']):
            infodata=[]
            for i in SecureCodesData.objects(used=False):
                infodata.append([i.mlevel, i.msecure, "OK", i.create_at])
            for i in SecureCodesData.objects(used=True):
                infodata.append([i.mlevel, i.msecure, "USED", i.create_at])
            session['mtoken'] = getToken(session['username'], session['create-time'])
            return render_template(securecodeFile, title=tr("secureSignHint"), homeShow=True, infodata=infodata,
                                   mtoken=session['mtoken'], publishShow=True, logoutShow=True, securecodeShow=True,
                                   controlTypesShow=controlClassesAvailable(session['username']),
                                   controlarticlesShow=controlArticlesAvailable(session['username']),
                                   controlusersShow=controlUsersAvailable(session['username']))
        else:
            return pageNotAllowed(tr("cannotintoInfo"))
    else:
        if 'mtoken' in session and request.form['token'] == session['mtoken'] and loggedinCheck() and \
                getuserControlAdminAvailable(session['username']):
            level = request.form['level']
            num = request.form['num']
            if str.isdigit(level) and str.isdigit(num):
                level = int(level)
                num = int(num)
                if level >= 1 and level <= 4 and num >= 1 and num <= 10:
                    for i in range(num):
                        createSecureCode(level)
        return redirect(securecodePath)


@app.route(controltypesPath, methods=['GET', 'POST'])
def controltypesNow():
    if request.method == 'GET':
        if not loggedinCheck():
            return pageNotAllowed(tr("loginFirstInfo"))
        if controlClassesAvailable(session['username']):
            session['mtoken'] = getToken(session['username'], session['create-time'])
            return render_template(controltypesFile, title=tr("controltypesSignHint"), homeShow=True, infodata=typelist,
                                   mtoken=session['mtoken'], publishShow=True, logoutShow=True, controlTypesShow=True,
                                   securecodeShow=getuserControlAdminAvailable(session['username']),
                                   controlarticlesShow=controlArticlesAvailable(session['username']),
                                   controlusersShow=controlUsersAvailable(session['username']))
        else:
            return pageNotAllowed(tr("cannotintoInfo"))
    else:
        if 'mtoken' in session and request.form['token'] == session['mtoken'] and loggedinCheck() and \
                controlClassesAvailable(session['username']):
            if request.form['type'] == "add":
                typename = request.form['typename']
                typevalue = request.form['typevalue']
                ok = True
                if typename and typevalue:
                    for i in typelist:
                        if i[0] == typevalue or i[1] == typename:
                            ok = False
                            break
                    if ok:
                        typelist.append([typevalue, typename])
                        TypeData(mtype=typevalue, name=typename).save()
            elif request.form['type'] == "delete":
                value = request.form['chosen']
                TypeData.objects(mtype=value).delete()
                for i in typelist:
                    if i[0] == value:
                        typelist.remove(i)
        return redirect(controltypesPath)


@app.route(controlarticlesPath, methods=['GET', 'POST'])
def controlarticlesNow():
    if request.method == 'GET':
        if not loggedinCheck():
            return pageNotAllowed(tr("loginFirstInfo"))
        if controlArticlesAvailable(session['username']):
            infodata = []
            for i in InfoData.objects():
                infodata.append(
                    [getShowType(i.type), getShowName(i.user), shortenTitle(i.title), shortenPassage(i.passage), i.id])
            session['mtoken'] = getToken(session['username'], session['create-time'])
            return render_template(controlarticlesFile, title=tr("publishedB"), homeShow=True, infodata=infodata,
                                   mtoken=session['mtoken'], publishShow=True, logoutShow=True,
                                   securecodeShow=getuserControlAdminAvailable(session['username']),
                                   controlTypesShow=controlClassesAvailable(session['username']),
                                   controlarticlesShow=controlArticlesAvailable(session['username']),
                                   controlusersShow=controlUsersAvailable(session['username']))
        else:
            return pageNotAllowed(tr("cannotintoInfo"))
    else:
        if 'mtoken' in session and request.form['token'] == session['mtoken'] and loggedinCheck() and \
                controlArticlesAvailable(session['username']):
            InfoData.objects(id=request.form['chosen']).delete()
        return redirect(controlarticlesPath)


@app.route(controlnormalusersPath, methods=['GET', 'POST'])
def controlusersNow():
    if request.method == 'GET':
        if not loggedinCheck():
            return pageNotAllowed(tr("loginFirstInfo"))
        if controlUsersAvailable(session['username']):
            infodata = []
            for i in UserData.objects(controlLevel=0):
                infodata.append(
                    [i.user, i.showname, i.create_at])
            session['mtoken'] = getToken(session['username'], session['create-time'])
            return render_template(controlnormalusersFile, title=tr("normalusersT"), homeShow=True, infodata=infodata,
                                   mtoken=session['mtoken'], publishShow=True, logoutShow=True,
                                   securecodeShow=getuserControlAdminAvailable(session['username']),
                                   controlTypesShow=controlClassesAvailable(session['username']),
                                   controlarticlesShow=controlArticlesAvailable(session['username']),
                                   controlusersShow=controlUsersAvailable(session['username']))
        else:
            return pageNotAllowed(tr("cannotintoInfo"))
    else:
        if 'mtoken' in session and request.form['token'] == session['mtoken'] and loggedinCheck() and \
                controlUsersAvailable(session['username']):
            UserData.objects(user=request.form['chosen']).delete()
        return redirect(controlnormalusersPath)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, threaded=True)
