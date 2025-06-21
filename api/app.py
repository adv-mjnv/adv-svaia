from flask import Flask, jsonify, make_response, request, flash, redirect, url_for, session, get_flashed_messages
import time
import toml
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, exc
from datetime import datetime
from flask_login import UserMixin

import flask_praetorian
from flask_praetorian.exceptions import AuthenticationError
from werkzeug.security import check_password_hash, generate_password_hash
import re
 

app = Flask(__name__, template_folder="templates")

def esperar_base_datos(db):
    intentos = 10
    while intentos > 0:
        try:
            db.session.execute(text("SELECT 1"))
            print("Base de datos disponible")
            return
        except exc.OperationalError:
            intentos -= 1
            print("Esperando base de datos... reintentando en 3s")
            time.sleep(3)
    raise Exception("No se pudo conectar a la base de datos")


app.config.from_file("config.toml", load=toml.load)
app.secret_key = app.config['SECRET_KEY']
db = SQLAlchemy()
db.init_app(app)

class Proyecto(db.Model):
    id = db.Column(db.Integer, primary_key=True) #al ser primary key, se autoincrementa, por default no hace falta indicar el id al crear un proyecto
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    fecha = db.Column(db.Date, nullable=False, default=datetime.now)
    fecha_modificacion = db.Column(db.DateTime, nullable=True, default=datetime.now, onupdate=datetime.now) #fecha de modificacion, se actualiza automaticamente al modificar el proyecto
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False) #clave foranea que referencia a la tabla usuario, así podemos relacionar cada proyecto con el usuario que lo creó
    criterios = db.Column(db.Text, nullable=True)
    dependencias = db.Column(db.Text, nullable=True)
    vulnerabilidades = db.Column(db.Text, nullable=True)
    # Relación inversa para acceder a los proyectos desde un usuario
    usuario = db.relationship('Usuario', backref='proyectos', lazy=True) #lazy=True es para que los proyectos se carguen solo cuando se accede a ellos, no al cargar el usuario

class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True) #hacemos username unique, no se puede repetir
    nombre = db.Column(db.String(100), nullable=False)
    apellidos = db.Column(db.String(100), nullable=False)
    correo = db.Column(db.String(150), nullable=False)
    password_hash = db.Column("password", db.Text, nullable=False)
    roles = db.Column(db.String(100), nullable=False, default="user") #roles del usuario, por defecto es user, ya que admin es el que tiene privilegios

    #definimos métodos de la clase usuario, que necesitamos para la autenticacion y validacion
    
    #devuelve el id unico del usuario, que se agrega al token 
    @property
    def identity(self):
        return self.id #self es el current_user
    
    #devuelve los roles del usuario, hacemos split porque se guardan en la tabla como un string "admin,user"
    @property
    def rolenames(self):
        return self.roles.split(',') if self.roles else []
    #entonces devuelve una lista de roles, necesitados para restringir acceso a funciones mediante decoradores

    #verificamos
    @property
    def password(self):
        return self.password_hash


    #cls es el equivalente a self, pero para la clase
    #usado al hacer login, devuelve el password del usuario
    @classmethod
    def lookup(cls, username): #metodo q a partir de username devuelve el usuario
        nusuario=db.session.scalar(db.select(Usuario).where(Usuario.username==username))
        return nusuario if nusuario else None
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    #busca usuario por su id, se usa cuando se reibe un token para saber de quien es
    @classmethod
    def identify(cls, id):
        nusuario=db.session.scalar(db.select(Usuario).where(Usuario.id==id))
        return nusuario if nusuario else None
    



with app.app_context():
    esperar_base_datos(db)
    db.create_all()
    print("Tablas creadas correctamente.")


#----------PRAETORIAN
app.config['JWT_ACCESS_LIFESPAN'] = {'minutes': app.config['JWT_ACCESS_LIFESPAN']}
app.config['JWT_REFRESH_LIFESPAN'] = {'minutes': app.config['JWT_REFRESH_LIFESPAN']}

praetorian= flask_praetorian.Praetorian()
praetorian.init_app(app, Usuario)

@app.route('/api/login_flask', methods=['POST'])
def login_flask():
    if request.is_json:
        try:
            nusuario=request.json
            username=nusuario["username"]
            npassword=nusuario["password"]
            user=praetorian.authenticate(username, npassword) #autenticamos al usuario, password en texto plano
            access_token=praetorian.encode_jwt_token(user) #generamos el token
            return jsonify(access_token=access_token), 200 #devolvemos el token  al cliente en el cuerpo de la respuesta
        except AuthenticationError:
            return jsonify({"error": "credenciales erroneas"}), 401
        except Exception as e:
            #raise e
            return jsonify({"error": str(e.__class__)}), 500 #mostramos la clase de la excepcion

    else:
        return jsonify({"error": "Formato incorrecto"}), 406

"""
usaremos esta primera funcion principalmente, sin cookie

praetorian.authenticate() llama a user.lookup(username) y obtiene dicho usuario, 
luego hace user.password y obtiene el hash e internamente hace check_password_hash de ambos
si no existe el usuario o la psswd es incorrecta, 
lanza una excepcion AuthenticationError, que la capturamos
tambien puede haber otros errores internos (como con la base de datos o el encode token)
que tambien capturamos

luego, si en una ruta da error flask_praetorian.auth_required lanza un error 401, que debemos capturar en web
"""


@app.route('/api/login_js', methods=['POST'])
def login_js():
    if request.is_json:
        nusuario=request.json
        username=nusuario["username"]
        password=nusuario["password"]
        user=praetorian.authenticate(username, password) #autenticamos al usuario, password en texto plano
        # y el flujo de codigo no sigue, por tanto, al cliente le devuelve un status code distinto de 200
        access_token=praetorian.encode_jwt_token(user) #generamos el token

        response= make_response(jsonify({"ok":True}),200) # en lugar de poner el token en el cuerpo de la respuesta, envia mnsj de okay
        response.set_cookie('access_token', access_token, httponly=True, secure=True, samesite='Strict') # y se guarda el token en una cookie
        return response #devolvemos el token  al cliente
    else:
        return jsonify({"error": "Formato incorrecto"}), 406





#-------PROYECTOS


#devolver la lista de proyectos
@app.route("/api/proyectos")
@flask_praetorian.auth_required
def get_proyectos():
    nusuario = flask_praetorian.current_user()

    if 'admin' in nusuario.rolenames:
        proyectos = db.session.scalars(
            db.select(Proyecto).order_by(Proyecto.fecha.desc())
        ).all()
    else:
        proyectos = db.session.scalars(
            db.select(Proyecto).where(Proyecto.id_usuario == nusuario.id).order_by(Proyecto.fecha.desc())
        ).all()

    lista_proyectos = []
    for proyecto in proyectos:
        try:
            criterios = json.loads(proyecto.criterios) if proyecto.criterios else {}
        except json.JSONDecodeError:
            criterios = {}

        lista_proyectos.append({
            "id": proyecto.id,
            "nombre": proyecto.nombre,
            "descripcion": proyecto.descripcion,
            "fecha": proyecto.fecha,
            "fecha_modificacion": proyecto.fecha_modificacion,
            "id_usuario": proyecto.id_usuario,
            "criterios": criterios,
            "dependencias": proyecto.dependencias,
            "vulnerabilidades": proyecto.vulnerabilidades
        })

    return jsonify(lista_proyectos)



import json

#insertar nuevo proyecto a la bdd
@app.post('/api/proyecto/add') 
@flask_praetorian.auth_required
def api_proyecto_add():
    if request.is_json:
        data = request.json
        criterios_json = json.dumps(data.get("criterios", {}))  #serializa

        p = Proyecto(
            nombre=data["nombre"],
            descripcion=data.get("descripcion", ""),
            criterios=criterios_json,
            dependencias=data.get("dependencias", ""),
            vulnerabilidades=data.get("vulnerabilidades", ""),
            id_usuario=flask_praetorian.current_user().id
        )

        db.session.add(p) 
        db.session.commit()
        return jsonify({'id': p.id}), 200
    else:
        return jsonify({"error": "Formato incorrecto"}), 406



#editar un proyecto en la base de datos
@app.put('/api/proyecto/editar/<int:id>') 
@flask_praetorian.auth_required
def api_proyecto_editar(id):
    if request.is_json:
        nproyecto = request.json
        nusuario=flask_praetorian.current_user()
        if 'admin' not in nusuario.rolenames:
            p = db.one_or_404(db.select(Proyecto).where(Proyecto.id==id, Proyecto.id_usuario == nusuario.id))
        else:
            p = db.one_or_404(db.select(Proyecto).where(Proyecto.id == id))
        p.nombre=nproyecto["nombre"]
        p.descripcion=nproyecto["descripcion"]
        db.session.commit()
        return jsonify({'id':p.id}), 200
    else:
        return jsonify({"error": "Formato incorrecto"}), 406


#eliminar un proyecto
@app.delete('/api/proyecto/delete/<int:id>')
@flask_praetorian.auth_required
def api_proyecto_delete(id):
    nusuario=flask_praetorian.current_user()
    if 'admin' not in nusuario.rolenames:
        p = db.one_or_404(db.select(Proyecto).where(Proyecto.id == id, Proyecto.id_usuario==nusuario.id))
    else:
        p = db.one_or_404(db.select(Proyecto).where(Proyecto.id == id))
    db.session.delete(p)
    db.session.commit()
    return jsonify({"id": id}), 200


def evaluar_aceptabilidad(criterios, vulnerabilidades_raw):
    """
    Evalúa si un proyecto cumple los criterios definidos.
    Devuelve una tupla (bool, lista_de_motivos_de_rechazo)
    """
    motivos = []

    if not criterios:
        return True, []  #sin criterios, se acepta

    vulnerabilidades = [v for v in vulnerabilidades_raw.split('\n') if v.strip()]
    total = len(vulnerabilidades)

    # -----------CRITERIO 1: TOTAL
    if "Criterio de total de vulnerabilidades" in criterios:
        try:
            max_total = int(re.findall(r'\d+', criterios["Criterio de total de vulnerabilidades"])[0])
            if total > max_total:
                motivos.append(f"Supera el número máximo de vulnerabilidades permitidas ({total}>{max_total})")
        except:
            motivos.append("Error al interpretar el criterio de total de vulnerabilidades")

    # -----------CRITERIO 2: SOLUCIONABILIDAD
    if "Criterio de solucionabilidad" in criterios:
        solucionables = sum(1 for v in vulnerabilidades if any(x in v.lower() for x in ["solucionado", "fixed", "patch"]))
        try:
            requerido = int(re.findall(r'\d+', criterios["Criterio de solucionabilidad"])[0])
            porcentaje = (solucionables / total) * 100 if total > 0 else 0
            if porcentaje < requerido:
                motivos.append(f"Porcentaje de vulnerabilidades solucionables insuficiente ({int(porcentaje)}% < {requerido}%)")
        except:
            motivos.append("Error al interpretar el criterio de solucionabilidad")

    # -----------CRITERIO 3: CVSS
    if "Criterio de nivel máximo" in criterios:
        try:
            max_cvss = float(re.findall(r'\d+(?:\.\d+)?', criterios["Criterio de nivel máximo"])[0])
            niveles = re.findall(r'cvss[:=]?\s*(\d+(?:\.\d+)?)', vulnerabilidades_raw.lower())
            niveles_float = [float(n) for n in niveles]
            if any(n > max_cvss for n in niveles_float):
                motivos.append(f"Una o más vulnerabilidades superan el nivel CVSS permitido (> {max_cvss})")
        except:
            motivos.append("Error al interpretar el criterio de nivel máximo CVSS")

    # -----------CRITERIO 4: CÁLCULO COMBINADO
    if "Criterio de cálculo combinado" in criterios:
        try:
            peso_total = 0
            for v in vulnerabilidades:
                peso = 1
                if "critica" in v.lower() or "critical" in v.lower():
                    peso += 2
                if "cvss" in v.lower():
                    match = re.search(r'cvss[:=]?\s*(\d+(?:\.\d+)?)', v.lower())
                    if match:
                        peso += float(match.group(1)) / 10 
                peso_total += peso
            max_peso = float(re.findall(r'\d+(?:\.\d+)?', criterios["Criterio de cálculo combinado"])[0])
            if peso_total > max_peso:
                motivos.append(f"El peso combinado de las vulnerabilidades es demasiado alto ({peso_total:.1f} > {max_peso})")
        except:
            motivos.append("Error al interpretar el criterio de cálculo combinado")

    return len(motivos) == 0, motivos


#obtener un proyecto especifico segun id para mostrar
@app.get('/api/proyecto/<int:id>')
@flask_praetorian.auth_required
def get_proyecto(id):
    nusuario = flask_praetorian.current_user()

    if 'admin' not in nusuario.rolenames:
        p = db.one_or_404(db.select(Proyecto).where(Proyecto.id == id, Proyecto.id_usuario == nusuario.id))
    else:
        p = db.session.scalar(db.select(Proyecto).where(Proyecto.id == id))

    propietario = db.session.scalar(db.select(Usuario).where(Usuario.id == p.id_usuario))

    try:
        criterios = json.loads(p.criterios) if p.criterios else {}
    except json.JSONDecodeError:
        criterios = {}

    es_aceptable, motivos_rechazo = evaluar_aceptabilidad(criterios, p.vulnerabilidades)

    return jsonify({
        "id": p.id,
        "nombre": p.nombre,
        "descripcion": p.descripcion,
        "fecha": p.fecha,
        "fecha_modificacion": p.fecha_modificacion,
        "id_usuario": p.id_usuario,
        "propietario": propietario.username,
        "criterios": criterios,
        "dependencias": p.dependencias,
        "vulnerabilidades": p.vulnerabilidades,
        "es_aceptable": es_aceptable,
        "motivos_rechazo": motivos_rechazo
    })





#-------USUARIOS

#devuelve lista de usuarios
@app.route("/api/usuarios")
@flask_praetorian.roles_required("admin") #this decorator will implicitly check @auth_required first
def get_usuarios():
    usuarios = db.session.scalars(db.select(Usuario)).all()
    lista_usuarios=[]
    for usuario in usuarios:
        lista_usuarios.append({
            "id": usuario.id,
            "username": usuario.username,
            "nombre": usuario.nombre,
            "apellidos": usuario.apellidos,
            "correo": usuario.correo,
            "password": usuario.password,
            "roles": usuario.roles
        })
    return jsonify(lista_usuarios)

@app.post('/api/usuario/add') #insertar nuevo usuario a la bdd
@flask_praetorian.roles_required("admin")
def api_usuario_add():
    if request.is_json:
        nusuario = request.json
        existe=db.session.scalar(db.select(Usuario).where(Usuario.username == nusuario["username"]))
        if existe:
            return jsonify({"error": "El usuario ya existe"}), 400
        else:
            u = Usuario(username=nusuario["username"], nombre=nusuario["nombre"], apellidos=nusuario["apellidos"], correo=nusuario["correo"], password_hash=praetorian.hash_password(nusuario["password"])) 
            db.session.add(u) 
            db.session.commit()
            return jsonify({'id': u.id}), 200
    else:
        return jsonify({"error": "Formato incorrecto"}), 406


#editar un usuario en la base de datos
@app.put('/api/usuario/editar/<int:id>') 
@flask_praetorian.auth_required
def api_usuario_editar(id):
    if request.is_json:
        nusuario = request.json
        usuario_actual=flask_praetorian.current_user()
        if 'admin' not in usuario_actual.rolenames and usuario_actual.id!=id:
            return jsonify({"error": "No tienes permisos para acceder a esta pagina."}), 403
        else:
            existe=db.session.scalar(db.select(Usuario).where(Usuario.username == nusuario["username"], Usuario.id != id))
            if existe:
                return jsonify({"error": "Username ocupado"}), 400
            else:
                u = db.one_or_404(db.select(Usuario).where(Usuario.id == id))
                u.username=nusuario["username"]
                u.nombre=nusuario["nombre"]
                u.apellidos=nusuario["apellidos"]
                u.correo=nusuario["correo"]
                db.session.commit()
                return jsonify({'id':u.id}), 200
    else:
        return jsonify({"error": "Formato incorrecto"}), 406


#eliminar un usuario
@app.delete('/api/usuario/delete/<int:id>')
@flask_praetorian.roles_required("admin")
def api_usuario_delete(id):
    u = db.one_or_404(db.select(Usuario).where(Usuario.id == id))
    proyectos = db.session.scalars(db.select(Proyecto).where(Proyecto.id_usuario == id)).all()
    for proyecto in proyectos:
        db.session.delete(proyecto)
    db.session.delete(u)
    db.session.commit()
    return jsonify({"id": id}), 200

#obtener un usuario especifico segun su id
@app.get('/api/usuario/<int:id>')
@flask_praetorian.auth_required
def get_usuario(id):
    nusuario=flask_praetorian.current_user()
    if 'admin' not in nusuario.rolenames and nusuario.id!=id:
        return jsonify({"error": "No tienes permisos para acceder a esta pagina."}), 403
    else:
        if 'admin' not in nusuario.rolenames:
            u = db.one_or_404(db.select(Usuario).where(Usuario.id == id, Usuario.id==nusuario.id)) 
        else:
            u = db.one_or_404(db.select(Usuario).where(Usuario.id == id))
        return jsonify({
                "id": u.id,
                "username": u.username,
                "nombre": u.nombre,
                "apellidos": u.apellidos,
                "correo": u.correo,
                "password": u.password,
                "roles": u.roles
            }) 


#obtener un usuario especifico segun su username
@app.get('/api/usuario/username/<string:username>')
@flask_praetorian.auth_required
def get_usuario_user(username):
    u = db.one_or_404(db.select(Usuario).where(Usuario.username == username))
    return jsonify({
            "id": u.id,
            "username": u.username,
            "nombre": u.nombre,
            "apellidos": u.apellidos,
            "correo": u.correo,
            "password": u.password,
            "roles": u.roles
        }) 


#----------------CORS
@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"] = "*" #permitimos acceso a la API desde cualquier origen
    response.headers["Access-Control-Allow-Headers"] = "Content-Type" #permite header content-type
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE" #permite esos metodos
    return response




#------------Resumen de codigos http que usamos y sus signficados
"""
200--> ok, que la operacion salio bien

400--> bad request, que la peticion no es valida, por ejemplo
si hay un campo mal como el username repetido

401--> unauthorized, si el usuario no esta autenticado, o su token es invalido

403--> forbidden, su el usuario no tiene permiso (esta autenticado)

404--> not found, cuando el recurso no existe

406--> not acceptable, cuando el formato no se acepta, 
ej si se espera json y se recibe otra cosa

500--> internal server error, para algun fallo inesperado
lo usamos si se da un error interno
"""