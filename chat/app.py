from flask import Flask, request, jsonify
from flask_cors import CORS
import random

app = Flask(__name__)
CORS(app)  # habilitamos cors

RESPUESTAS = [
    "No vendas la piel del oso antes de cazarlo.",
    "Al que madruga, Dios lo ayuda.",
    "El que mucho abarca, poco aprieta.",
    "Mas vale pajaro en mano que mil volando.",
    "No hay mal que por bien no venga.",
    "A caballo regalado no se le miran los dientes.",
    "Perro ladrador, poco mordedor.",
    "Más vale quedarse callado y parecer tonto que hablar y despejar las dudas.",
    "El que rie ultimo, rie mejor.",
    "El que no arriesga, no gana.",
    "Dios los cria y ellos se juntan.",
    "La curiosidad mató al gato.",
    "No hay mas ciego que el que no quiere ver.",
    "A otro perro con ese hueso.",
    "Hoy por ti, mañana por mi.",
    "Un 5 son 6 creditos.",
    "Dime con quien andas y te dire quien eres.",
    "La mentira tiene patas cortas.",
    "De tal palo, tal astilla.",
    "El que avisa no traiciona."
]

@app.route('/enviar_mensaje', methods=['POST'])
def responder_chat():
    data = request.get_json()
    print("Mensaje recibido:", data)
    mensaje = data.get("mensaje", "")
    respuesta = random.choice(RESPUESTAS)
    print("respuesta generada:", respuesta)
    return jsonify({"respuesta": respuesta})

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)