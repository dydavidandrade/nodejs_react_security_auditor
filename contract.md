# Auditor de seguridad senior para Nodejs + React ethical hacking

## Objetivos:

- Herramienta interna que evalúa la seguridad del código, reglas y la infraestructura de una aplicación Nodejs + React.
- Analizará el código y generará un informe de vulnerabilidades y configuraciones erróneas.
- Eres un ethical hacking con experiencia en Nodejs + React.

## Lenguaje:

- Javascript NodeJS

## herramientas:

- NPX
- herramientas open source para seguridad
- pnpm

## UI / UX:

- No tiene interfaz ni front ni nada es un script para terminal.

## Principios:

- SOLID
- Dependencias con pnmp y ultimas versiones LTS
- JSDoc todos los artefactos deben tener documentacion clara y en español

## Alcance:

- Nodejs + React application con todos sus frameworks y dependencias.

## Proceso

- En cualquier paso si hay dudas o preguntas se debe detener y hacerlas hasta que el humano apruebe

## Requerimiento único:

- El script se debe basar en la especificacion SEC.spec.md
- El script inicia con 1 parametro que es la URL de la aplicación objetivo de prueba.

### Pasos de ejecucion:

1.instalar todas las dependecias necesarias para procesar el script. 2. Ejecutar el script con el parametro de la URL. 3. El script debe leer todos los directorios del proyecto menos los que esten señalaldos como ingorar en el .gitignore. 4. para el backend es importante detectar si esta implementado con express o nestjs, luego revisar si tiene todos los middlewares de seguridad y si tiene helmet implementado. La idea es leer TODAS las rutas o todos los archivos que tengan inyecciones HTTP como @Get @Post @Put @Delete etc y saber si tienen armado una validacion de seguridad. adicional todo lo incuido en el archivo SEC.spec.md 5. para el frontend es importante detectar si esta implementado con react y que otras librerias esta usando. adicional todo lo incuido en el archivo SEC.spec.md 6. Generar reporte de vulnerabilidades y recomendaciones de seguridad en un archivo JSON, ademas de un reporte en texto plano para la terminal. Es importante que intente explicar como remediar la vulnerabilidad encontrada. 7. Crear todos los vectores de ataque y ejecutarlos a la URL que se pasa como parametro. 8. Limpieza de todos los artefactos creados

## Versionamiento y manual.

- En README.md debe mantener 2 secciones:

### Como ejecutar.

- Instrucciones claras y precisas para ejecutar el script.

### Versiones:

- tabla con version, fecha, caracteristica agregada.
