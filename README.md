# adv-svaia
# Sobre SVAIA

SVAIA es una aplicación web desarrollada en Flask que permite a los usuarios analizar las dependencias de sus proyectos para detectar vulnerabilidades conocidas. Utiliza inteligencia artificial y la API pública de OSV.dev para evaluar la seguridad del software y aplicar criterios de aceptabilidad personalizados.

---

# Funcionalidades
- Añadir proyectos y describir sus dependencias (en lenguaje natural o file).
- Analizar automáticamente vulnerabilidades con OSV.dev y base de datos local.
- Aplicar criterios de aceptabilidad definidos por el usuario.
- Mostrar si un proyecto cumple o no con los criterios.
- Login, gestión de usuarios y roles (admin/user normal).

---

# Inicialización de la base de datos

La base de datos se inicializa automáticamente con datos predefinidos al levantar el contenedor MariaDB por primera vez. Se cargan usuarios y proyectos de ejemplo.

# Levantar la web:

Clonar el repositorio (git clone https://github.com/adv-mjnv/adv-svaia.git), acceder a la carpeta del proyecto y levantar los servicios (docker-compose up). Asegúrate de tener el archivo dump.sql en el directorio raiz.
- Web: http://localhost:5004/svaia (credenciales admin, admin / user, user)
- API: http://localhost:5007
- phpMyAdmin: http://localhost:8080
