package com.example.utilities;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Component;

@Component
public class FileDownloadUtil {

    private Path foundFile;

    // [IA] Este atributo de clase (private Path foundFile) lo he eliminado. Estaba
    // compartido por todas las peticiones porque @Component crea un unico objeto
    // para toda la aplicacion: dos descargas simultaneas se pisaban el valor la una
    // a la otra y podian devolver ficheros equivocados. No hacia falta guardarlo,
    // asi que ahora es una variable local de metodo.

    public Resource getFileAsResource(String fileCode) throws IOException {

        /**
         * Buscar en la carpeta donde se han subido los archivos (imagenes de los
         * productos)
         * al servidor, a ver si hay alguno que comience por el fileCode suministrado,
         * es decir,
         * recibido como parametro en este metodo
         */

        Path dirPath = Paths.get("Files-Upload");

        // [IA] Comprobacion mia. Motivo: si la carpeta no existe, Files.list() lanza
        // NoSuchFileException (que es una IOException) y el controlador lo traducía a
        // un 500. Si la carpeta no esta, para quien pregunta el fichero simplemente
        // no existe, asi que devolvemos null -> 404.
        if (!Files.exists(dirPath)) {

            return null;
        }

        Path foundFile;

        // [IA] Aqui esta el bug que devolvia 500 en vez de 404: usabas
        // .findFirst().get(). El .get() de Optional es una bomba: si no encuentra
        // nada lanza NoSuchElementException, y esa excepcion es de tipo Runtime, no
        // IOException, asi que se escapaba de todos los catch y llegaba hasta el
        // contenedor de servlets como un 500. Con .orElse(null) no hay excepcion:
        // simplemente devuelve null, que es justo lo que el if de abajo ya esperaba
        // (y que hasta ahora era codigo muerto, porque nunca se cumplia).
        // Aprovecho para cerrar el Stream con try-with-resources, que es lo correcto
        // al trabajar con Files.list().
        try (Stream<Path> ficheros = Files.list(dirPath)) {

            foundFile = ficheros
                    .filter(file -> file.getFileName().toString().startsWith(fileCode))
                    .findFirst()
                    .orElse(null);

        } catch (IOException ioe) {

            // [IA] Este catch lo he anadido yo. El original era
            // "throw new IOException("Error fatal bucando el fichero ", ioe)"
            // que el controlador convertia en 500. Se mantiene como IOException
            // para que el siga distinguiendo un fallo real de disco/permisos (500)
            // de un fichero que simplemente no esta (404).
            throw new IOException("Error fatal buscando el fichero ", ioe);
        }

        if (foundFile != null)
            return new UrlResource(foundFile.toUri());

        return null;

    }
}
