import time
import toml
from flask import Flask, render_template, request, flash, redirect, url_for, session, get_flashed_messages, abort, request, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, func, exc
from datetime import datetime
import requests
import json
import re


from flask import abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from util import url_has_allowed_host_and_scheme

app = Flask(__name__, template_folder="templates")
app.config.from_file("config.toml", load=toml.load)
API_BASE = app.config['API_BASE_URL'] #hemos definido la URL de la API en el config, para que sea mas facil de usar, aqui la cargamos en este archivo
app.secret_key = app.config['SECRET_KEY']


"""
solo tenemos que cambiar las consultas a la base de datos por peticiones a la API
usamos requests para hacer las peticiones a la API, y json para convertir los datos a formato JSON
la API devuelve los datos en formato JSON, por lo que no es necesario hacer nada mas
"""

#clase cliente con los datos que devuelve la API
class Usuario(UserMixin):
    def __init__(self, data: dict):
        self.id=data['id']
        self.username=data['username']
        self.nombre = data['nombre']
        self.apellidos = data['apellidos']
        self.correo = data['correo']
        self.password_hash = data['password']
        self.roles=data['roles']

#-----------------------LOGIN


login_manager = LoginManager() #creamos objeto que gestiona el login
login_manager.init_app(app) #indicamos que trabaje sobre la app
login_manager.login_view = 'login' #si alguien intenta entrar a ruta protegida lleva a funcion login(), en ruta /login
login_manager.login_message = 'Debes iniciar sesión para acceder a esta página.'
login_manager.login_message_category = 'info'


def hash(password): # codificar contraseña
    return generate_password_hash(password, method='pbkdf2:sha512', salt_length=16)

def check(password, hash): # verificar contraseña
    return check_password_hash(hash, password)

#Funcion para generar los tokens de acceso que enviaremos en el header de las peticiones a la API:
def get_token_h():
    token = session.get('access_token') #si ya existe el token en la session, lo guardamos
    if not token:
        return {} #si no existe no hacemos nada, devolvemos vacio, gestionaremos la creacion de los tokens cuando los usuarios inicien sesion por 1ra vez
    return {'Authorization': f'Bearer {token}'} #devolvemos lo que pasaremos en el header con el token

@login_manager.user_loader #cada vez que se necesita saber el usuario logueado, se llama a esta funcion
def load_user(user_id):
    #obtenemos el token de acceso para las peticiones a la API
    headers = get_token_h()
    r = requests.get(f"{API_BASE}/api/usuario/{user_id}", headers=headers)
    if r.ok:
        return Usuario(r.json())
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        credenciales = {
            'username':request.form['username'],
            'password':request.form['password']
        }
        r = requests.post(f"{API_BASE}/api/login_flask", json=credenciales) #peticion a la API para obtener el usuario, le pasamos el username  
        if r.status_code != 200:
            flash("Usuario o contraseña incorrectos", "danger") 
            return redirect(url_for('login'))
        token = r.json()['access_token']
        #Guardar el token en la sesión para que esté disponible en el resto del código _Flask_ de la aplicación 
        session['access_token'] = token
        #obtenemos los datos del usuario desde la api para poder hacer login con flask-login
        r_usuario=requests.get(f"{API_BASE}/api/usuario/username/{credenciales['username']}", headers={"Authorization": f"Bearer {token}"})
        if r_usuario.status_code != 200:
            flash("Error al obtener el usuario", "danger")
            return redirect(url_for('login'))
        u_data=r_usuario.json()
        user=Usuario(u_data)
        login_user(user) #iniciamos sesión con flask-login si todo ha ido bien
        flash("Has iniciado sesión correctamente", "success")

        next = request.form.get('next', '/svaia') #next es la url que se pidio abrir y necesitaba login, si no existe se redirige a svaia
        if not url_has_allowed_host_and_scheme(next, request.host): #verificamos que next sea seguro
            return abort(400)                
        return redirect(next) #si es seguro, redireccionamos a next
    return render_template('login.html') #si se trata de un GET, se muestra el login

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Cerrar sesión con Flask-Login
    session.pop('access_token', None) #limpiar el token de acceso de la sesión
    session.pop('_flashes', None)  #limpiamos los mensajes flash para que no se acumulen
    flash('Has cerrado la sesión.', 'info')
    return redirect(url_for('login'))



#-----------------------RUTAS GENERALES


@app.route ("/svaia")
def svaia():
    return render_template("svaia.html")

@app.route ("/chat")
@login_required
def chat():
    #obtenemos el token de acceso para las peticiones a la API
    headers = get_token_h()
    r = requests.get(f"{API_BASE}/api/proyectos", headers=headers)
    proyectos = r.json()
    """
    hacemos la peticion a la API para obtener los proyectos pasandole el token en el headers
    la api se encargar de ver si es el admin para mostrarlos todos, o solo los del usuario concreto
    si  no hay proyectos, solo devuelve una lista vacia, no hay fallo
    le pasamos al chat la lista de proyectos que tiene que mostrar
    """
    return render_template("chat.html", proyectos=proyectos)
    
@app.route("/mi_cuenta")
@login_required
def mi_cuenta():
    return render_template("mi-cuenta.html", u=current_user)



#----REPORTE
@app.route("/proyecto/<int:id>/descargar_reporte")
@login_required
def descargar_reporte(id):
    headers = get_token_h()
    r = requests.get(f"{API_BASE}/api/proyecto/{id}", headers=headers)

    if r.status_code != 200:
        flash("No se pudo descargar el reporte", "danger")
        return redirect(url_for("proyecto", id=id))

    proyecto = r.json()
    vulnerabilidades = proyecto.get("vulnerabilidades", "")

    if not vulnerabilidades.strip():
        vulnerabilidades = "No se encontraron vulnerabilidades."

    # Crear contenido del .txt
    contenido = f"Reporte de vulnerabilidades - Proyecto: {proyecto['nombre']}\n\n"
    contenido += vulnerabilidades

    return Response(
        contenido,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename=Reporte_{proyecto['nombre'].replace(' ', '_')}.txt"
        }
    )



#-----------------------GESTION DE PROYECTOS

@app.route("/proyecto_nuevo", methods=["GET", "POST"])
@login_required
def proyecto_nuevo():
    headers = get_token_h()

    if request.method == "POST":
        nombre_p = request.form["nombre"]
        descripcion = request.form.get("descripcion", "")

        #criterios seleccionados
        criterios_dict = {}

        if request.form.get("criterio_total_check"):
            val = request.form.get("criterio_total_valor", "")
            if val:
                criterios_dict["Criterio de total de vulnerabilidades"] = f"{val} vulnerabilidades"

        if request.form.get("criterio_sol_check"):
            val = request.form.get("criterio_sol_valor", "")
            if val:
                criterios_dict["Criterio de solucionabilidad"] = f"{val}%"

        if request.form.get("criterio_nivel_check"):
            val = request.form.get("criterio_nivel_valor", "")
            if val:
                criterios_dict["Criterio de nivel máximo"] = f"{val} CVSS"

        if request.form.get("criterio_combo_check"):
            val = request.form.get("criterio_combo_valor", "")
            if val:
                criterios_dict["Criterio de cálculo combinado"] = f"{val} pts"

        # === EXTRAER DEPENDENCIAS ===
        dependencias_texto = ""
        archivo = request.files.get("archivo_dependencias")
        if archivo and archivo.filename:
            dependencias_texto = archivo.read().decode("utf-8")
        else:
            dependencias_texto = request.form.get("dependencias_natural", "")

        # Limpiar dependencias (extraer nombre y versión)
        import re
        dependencias_detectadas = []
        patron = r'(\b[a-zA-Z0-9_\-]+)\s+([0-9]+(?:\.[0-9]+)*)'
        matches = re.findall(patron, dependencias_texto)
        for paquete, version in matches:
            dependencias_detectadas.append(f"{paquete.lower()} {version}")

        dependencias_limpias = "\n".join(dependencias_detectadas)

        # === ANALIZAR VULNERABILIDADES ===
        base_local = {
            "django": {
                "2.2": ["CVE-2019-12345: SQL Injection en admin panel"],
            },
            "flask": {
                "1.0": ["CVE-2018-1234: SSTI en Jinja2"],
            },
            "express": {
                "4.17.1": ["CVE-2021-12345: Prototype Pollution"]
            }
        }

        resultado_vulns = []
        texto = dependencias_limpias.lower()

        #Búsqueda en base local que hemos definido
        for paquete, versiones in base_local.items():
            if paquete in texto:
                for version, vulns in versiones.items():
                    if version in texto and vulns:
                        for v in vulns:
                            resultado_vulns.append(f"{paquete} {version}: {v}")

        #Consulta a OSV.dev
        posibles_paquetes = re.findall(r'\b[a-zA-Z0-9\-_]+\b', texto)
        consultados = set()

        for nombre in posibles_paquetes:
            nombre = nombre.lower()
            if nombre in consultados:
                continue
            consultados.add(nombre)
            r_osv = requests.post("https://api.osv.dev/v1/query", json={"package": {"name": nombre, "ecosystem": "PyPI"}})
            if r_osv.ok:
                data = r_osv.json()
                for v in data.get("vulns", []):
                    resumen = v.get("summary", "Vulnerabilidad detectada (no tenemos resumen sobre está vulnerabilidad).")
                    resultado_vulns.append(f"{nombre}: {resumen}")
        vulnerabilidades = "\n".join(resultado_vulns) if resultado_vulns else "No se encontraron vulnerabilidades conocidas."

        # === ENVIAR A LA API ===
        datos_formulario = {
            "nombre": nombre_p,
            "descripcion": descripcion,
            "criterios": criterios_dict,
            "dependencias": dependencias_limpias,
            "vulnerabilidades": vulnerabilidades
        }
        r = requests.post(f"{API_BASE}/api/proyecto/add", json=datos_formulario, headers=headers)
        if r.status_code == 200:
            flash(f"Proyecto {nombre_p} añadido con éxito.", "success")
            return redirect(url_for("chat"))
        else:
            flash("Error al crear el proyecto", "danger")
            return redirect(url_for("proyecto_nuevo"))

    return render_template("nuevo-proyecto.html")


@app.route("/proyecto/editar/<int:id>", methods=["GET", "POST"])
@login_required
def proyecto_editar(id):
    #obtenemos el token de acceso para las peticiones a la API
    headers = get_token_h()
    if request.method=="GET":
        #la API se encarga de ver si es el admin o no, pues le pasamos el token
        r=requests.get(f"{API_BASE}/api/proyecto/{id}", headers=headers) #peticion a la api pasandole el token
        if r.status_code==404:
            flash("Proyecto no encontrado", "danger")
            return redirect(url_for("chat"))
        elif r.status_code==406:
            flash("Formato incorrecto", "danger")
            return redirect(url_for("chat"))
        proyecto=r.json()
        return render_template("editar-proyecto.html", p=proyecto) #si la peticion es un GET, lo mandamos a la pagina para editar el proyecto
    
    #si es POST, cogemos los datos introducidos en el formulario
    #si es admin puede editar cualquier proyecto, esto lo comprueba la api con el token
    datos_formulario = {
        'nombre': request.form['nombre'],
        'descripcion': request.form['descripcion']
    }
    r = requests.put(f"{API_BASE}/api/proyecto/editar/{id}", json=datos_formulario, headers=headers)
    if r.ok:
        flash(f"Proyecto {datos_formulario['nombre']} modificado con éxito.", "success")
        session.pop('_flashes', None)
        return redirect(url_for("chat")) #si todo ha ido bien, avisa y devuelve al chat
    flash("Error al modificar el  proyecto", "danger")
    return redirect(url_for("chat")) #si ha habido algun fallo, vuelve a chat
        
"""esta ruta es para editar el proyecto. recibe el id, lo busca, y si se trata de GET te redirige a editar ese proyecto
(p=p le esta enviando como proyecto el que encontró con el ID especificado en la url)
si se trata de POST, recibe el formulario y lo modifica"""

 #Para eliminar un proyecto, solo tenemos que pasarle al método delete la instancia de una clase proyecto  
 #En el caso de que haya una clave foránea que usa algo de la tabla, antes de eliminar la tabla necesitamos eliminar esa clave foránea que depende, ya luego eliminamos la tabla
@app.route("/proyecto/eliminar/<int:id>")
@login_required
def proyecto_eliminar(id):
    #obtenemos el token de acceso para las peticiones a la API
    headers = get_token_h()
    r=requests.delete(f"{API_BASE}/api/proyecto/delete/{id}", headers=headers)
    #la api se encarga de ver si es admin o no, para saber si puede eliminar cualquiera o solo los suyos
    if r.status_code==200:
        flash("Proyecto eliminado con éxito.", "success")
    else:
        flash("Error al eliminar el proyecto", "danger")
    return redirect(url_for("chat"))
    
"""recibe el id, busca el proyecto con ese id, y lo elimina
despues te redirige al url de chat, donde estan todos los proyectos menos ese
hay dos formas de acceder, puede ser desde el chat apretando el cubo de eliminar (entonces el icono esta linkeado a la ruta eliminar)
o desde la pagina proyectyo (mas abajo) donde el boton eliminar se linkea tambien a este url
luego de eliminar, te devuelve al chat"""

@app.route("/proyecto/<int:id>")
@login_required
def proyecto(id=None):
    headers = get_token_h()
    r = requests.get(f"{API_BASE}/api/proyecto/{id}", headers=headers)
    if r.status_code == 404:
        flash("Proyecto no encontrado", "danger")
        return redirect(url_for("chat"))

    proyecto = r.json()

    #Convertimos p["criterios"] de JSON string a dict
    criterios_dict = {}
    if proyecto.get("criterios"):
        try:
            criterios_dict = proyecto["criterios"]
        except json.JSONDecodeError:
            criterios_dict = {}

    return render_template("proyecto.html", p=proyecto, propietario=proyecto["propietario"], criterios=criterios_dict)
    
"""cuando apreto sobre un proyecto, me abre la pagina proyecto.html que tiene la opcion de editar o eliminar
entonces desde esa pagina, linkeo esos botones a la pagina de editar, o eliminar
es decir, que al apretar ese boton, van al url /proyecto/editar o /proyecto/eliminar y se hace lo que se especifica en la ruta"""



#-----------------------GESTION DE USUARIOS

@app.route("/usuarios")
#solo puede entrar el admin
@login_required
def listar_usuarios():
    #obtenemos el token de acceso para las peticiones a la API
    headers = get_token_h()
    r=requests.get(f"{API_BASE}/api/usuarios", headers=headers)
    if r.status_code==401:
        flash("Necesitas iniciar sesión para acceder a esta página.", "danger")
        return redirect(url_for("login"))
    elif r.status_code==403:
        flash("No tienes permiso para acceder a esta página.", "danger")
        return redirect(url_for("svaia"))
    if not r:
        flash("Error al obtener la lista de usuarios", "danger")
        return redirect(url_for("svaia"))
    usuarios = r.json()
    return render_template("usuarios.html", usuarios=usuarios)
    #aqui no ahcemos lo de la clase usuario pues lo que devuelve es una lista de usuarios y lo usaremos en una plantilla con jinja
    
@app.route("/usuarios/nuevo", methods=["GET", "POST"])
@login_required
def usuario_nuevo():
    #obtenemos el token de acceso para las peticiones a la API
    headers = get_token_h()
    if request.method == "POST":
        #solo el admin puede crear usuarios
        datos_formulario = {
            'username': request.form['username'],
            'nombre': request.form['nombre'],
            'apellidos': request.form['apellidos'],
            'correo': request.form['correo'],
            'password': request.form['password'] #mandamos la contraseña 
        }
        r=requests.post(f"{API_BASE}/api/usuario/add", json=datos_formulario, headers=headers)
        #la api se encarga de ver si es admin o no
        if r.status_code==401:
            flash("Necesitas iniciar sesión para acceder a esta página.", "danger")
            return redirect(url_for("login"))
        elif r.status_code==403:
            flash("No tienes permisos para acceder a esta página.", "danger")
            return redirect(url_for("svaia"))
        #arriba fallos de autenticacion, abajo fallos de la creacion
        if r.status_code == 200:
            flash(f"Usuario {datos_formulario['username']} añadido con éxito.", "success")
            return redirect(url_for("listar_usuarios"))
        elif r.status_code == 400:
            flash(f"El nombre de usuario {datos_formulario['username']} ya existe.", "danger")
            return redirect(url_for("usuario_nuevo"))
        else:
            flash("Error al crear el usuario", "danger")
            return redirect(url_for("usuario_nuevo"))          
    else:
        #si la peticion es un GET, lo mandamos a la pagina para crear el usuario
        return render_template("nuevo-usuario.html")

@app.route("/usuarios/editar/<int:id>", methods=["GET", "POST"])
@login_required
def usuario_editar(id):
    #obtenemos el token de acceso para las peticiones a la API
    headers = get_token_h()
    if request.method == "POST":
        datos_formulario = {
            'username': request.form["username"],
            'nombre': request.form["nombre"],
            'apellidos': request.form["apellidos"],
            'correo': request.form["correo"]
        }
        r=requests.put(f"{API_BASE}/api/usuario/editar/{id}", json=datos_formulario, headers=headers) #peticion a la API para editar el usuario, le pasamos el id del usuario que queremos editar y los datos para editar
        if r.status_code == 200:
            flash(f"Usuario {datos_formulario['username']} editado con éxito.", "success")
            session.pop('_flashes', None)
            return redirect(url_for("listar_usuarios"))
        elif r.status_code == 400:
            flash(f"El nombre de usuario {datos_formulario['username']} ya está en uso. Por favor, elige otro.", "danger")
            return redirect(url_for("usuario_editar", id=id))
        elif r.status_code == 401:
            flash("Necesitas iniciar sesión para acceder a esta página.", "danger")
            return redirect(url_for("login"))
        elif r.status_code==403:
            flash("No tienes permiso para acceder a esta página.", "danger")
            return redirect(url_for("svaia"))
        else:
            flash("Error al editar el usuario", "danger")
            return redirect(url_for("usuario_editar", id=id))
    else:
        #si la petición es GET, se va a mandar a la pagina para editar el usuario
        r=requests.get(f"{API_BASE}/api/usuario/{id}", headers=headers)
        if r.status_code == 403:
            flash("No tienes permisos para acceder a esta página.", "danger")
            return redirect(url_for("svaia"))
        if not r:
            flash("Usuario no encontrado", "danger")
            return redirect(url_for("listar_usuarios"))
        u=Usuario(r.json())
        return(render_template("editar-usuario.html", u=u)) #si la peticion es un GET, lo mandamos a la pagina para editar el usuario

    
@app.route("/usuarios/eliminar/<int:id>")
@login_required
def usuario_eliminar(id=None):
    #obtenemos el token de acceso para las peticiones a la API
    headers = get_token_h()
    r=requests.delete(f"{API_BASE}/api/usuario/delete/{id}", headers=headers)
    if r.status_code==401:
        flash("Necesitas iniciar sesión para acceder a esta página.", "danger")
        return redirect(url_for("login"))
    elif r.status_code==403:
        flash("No tienes permisos para acceder a esta página.", "danger")
        return redirect(url_for("svaia"))
    elif r.status_code == 200:
        flash("Usuario y sus proyectos eliminados con éxito.", "success")
        session.pop('_flashes', None)
    else:
        flash("Error al eliminar el usuario", "danger")
    return redirect(url_for("listar_usuarios"))