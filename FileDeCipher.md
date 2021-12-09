#Cifrador descifrador de archivos

##Objetivo
Permitir al usuario cifrar y descifrar archivos haciendo uso de una contraseña. El algoritmo utilizado para los procesos de cifrado y descifrado es AES, en modalidad CBC y con padding PKCS5.

##Solución
Para la creación de este programa se dividió el código en diferentes métodos.
Se crearon dos métodos principales: encryptFile y decryptFile. El primero recibe un archivo cualquiera y lo cifra usando una contraseña dada. El segundo hace el proceso contrario, recibe un archivo cifrado y lo descifra usando una contraseña introducida por el usuario.
Para poder cifrar y descifrar el archivo con una contraseña, primero se crea una llave a partir de dicha contraseña. Esta llave se obtiene con la función de derivación PBKDF2 en 65536 iteraciones. La clave obtenida es de 128 bits y la sal usada en la contraseña se encuentra como constante en el programa, es decir se usa la misma sal para todas las llaves. Además de una clave también es necesario para ambos procesos la utilización de un vector de inicialización, el cual se forma a partir de bytes aleatorios dispuestos en un arreglo haciendo uso de la clase SecureRandom.
Para la verificación del contenido de los archivos descifrados se utiliza un hash SHA-1, el cual se guarda en el archivo cifrado, si el hash del archivo descifrado y el hash guardado previamente, coinciden, quiere decir que la contraseña introducida es correcta y el contenido descifrado es correcto, de lo contrario se confirma que la contraseña es incorrecta y el contenido descifrado, al ser simple ruido, se descarta. 

La *dificultad* general con la que nos encontramos al hacer este programa fue el desconocimiento de las clases y funciones necesarias para implementar las funciones de cifrado y descifrado.

##Conclusión
Es importante tener una contraseña fuerte para poder asegurar la seguridad de los archivos encriptados, ya que por más fuerte y confiable que sea un algoritmo de cifrado, un simple ataque de fuerza bruta podría vulnerar la confidencialidad de la información.
