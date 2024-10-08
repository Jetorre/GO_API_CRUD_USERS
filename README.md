# GO_API_CRUD_USERS
API en Go que realiza:
* CRUD  para la creación, eliminación y listado de 1 o todos los usuarios.
* Uso de JWT en donde el token tiene vigencia unicamente de 1 minuto, adicionalmente el token solo puede ser usado una unica vez ya que se valida el token contra una base de datos.
* La autenticación para obtener el token es basic pero para listar, crear o borrar es con autenticación Bearer.
* Los datos importantes como usuarios, contraseñas, host, port, entre otros se encuentran cifrados usando AES.
* Uso de HTTPS.