<?php
namespace App\Http\Traits;
use Storage;
use Auth;
use DB;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/*
 ------------------Orden de Proceso general----------------
 -> Instancia La clase pasandole la url del servicio, $instancia  = new SoapEater;
 -> Luego pasale la vista o texto que sera convertido a XML $instancia->setBody($vista)
 *Esto puede ser un string o un array, y puede fusionarlo o no con los valores por defecto
 ->Luego si necesitas una cabezera particular puecdes pasarle la cabezera $instancia->setHead($cabezera)
 *Esto puede ser un string o un array, y puede fusionarlo o no con los valores por defecto
 ->por Ultimo solo tienes que enviar la peticion $instancia->send()
 *si necesitas almacenar la respuesta basta conque almacenes en una vairable la ejecucion del metodo: $mi_respuesta =  $instancia->send();
 *la respuesta incluye un Status : true o false,  response : original , y un mentodo generarFILE par a guardar el response como XML
 en una ruta especifica si asi se necesita.
 *para hacer esto ultimo debe ejecutar el closure y pasale lam ruta donde se almacenara el valor  ($mi_respuesta)($RUTA_A_ALMACENAR)

 /----PENDIENTE-----/
 -> Todos los metodos retornan un status  true / false;
 -> y un error en caso de existir un error,
*/

class SoapEater
{
    function __construct( $url, $head = null, $body = null)
    {
        $this->url = $url;
        $this->head = $head ? $head : [ 'Content-Type: text/xml;charset=UTF-8'];
        $this->body = $body ? $body : null;
        $this->curl = null;
        $this->config = [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => 0,
            CURLOPT_SSL_VERIFYHOST => 0,
        ];
        $this->response = null;
    }

    // setear una configuracion  de la peticion
    // en caso de string púde asignar solo el valor del string o pushearlo a las configuraciones por defecto
    // en caso de Array es igual puede reescribir o aregar a las config por defecto
    public function setConfig( $config, $merge = false )
    {
        if( is_array($config) ){
            if($merge){
                foreach ($config as $key => $value) {
                    $this->config[$key] = $value;
                }
            }
            else{
                $this->config = $config;
            }
        }
        else {
            if($merge){
                $this->config = [$this->config, $config];
            }
            else{
                $this->config = $config;
            }
        }
    }

    // setear configuracion del head
    public function setHead( $config, $merge = false )
    {
        try {
            if( is_array($config) ){
                if($merge){
                    $this->head = array_merge($this->head, $config);
                }
                else{
                    $this->head = $config;
                }
            }
            else {
                if($merge){
                    $this->head = [$this->head, $config];
                }
                else{
                    $this->head = $config;
                }
            }

            return (object)[
                'status' => true
            ];
        }
        catch (\Exception $e) {
            return (object)[
                'status' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    // setear url de la peticion
    public function setUrl($url)
    {
        try {
            if( filter_var($url, FILTER_VALIDATE_URL) ){
                $this->url  = $url;

                return (object)[
                    'status' => true
                ];
            }
            else{
                throw new \Exception('Url incorrecta');
            }
        }
        catch (\Exception $e) {
            return (object) [
                'error' => $e-getMessage(),
                'status'=> false,
            ];
        }
    }

    //generar xml de la vista
    public function setBody( $vista )
    {
        try {
            $doc = new \DOMDocument();
            $doc->encoding = 'utf-8';
            $doc->xmlVersion = '1.0';
            $doc->formatOutput = true;
            $doc->loadXML( html_entity_decode( $vista ) );
            $xml = $doc->saveXML();
            $this->body = $xml;

            return (object)[
                'status'=> true,
            ];
        }
        catch (\Exception $e) {
            return (object)[
                'status'=> false,
                'error' => $e->getMessage(),
            ];
        }
    }

    // GENERAR XML FIRMADO PENDIENTE POR VERIFICAR FUNCIONALIDAD
    public function setBodyFirmado($vista, $ruta_firma, $options = ["insertBefore" => false])
    {
        try {
            // Load the XML to be signed
            $doc = new \DOMDocument();
            $doc->encoding = 'utf-8';
            $doc->xmlVersion = '1.0';
            $doc->loadXML( html_entity_decode( $vista ) );

            $objWSSE = new WSSESoap($doc, true);

            /* add Timestamp with no expiration timestamp */
            $objWSSE->addTimestamp();

            /* create new XMLSec Key using AES256_CBC and type is private key */
            $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));

            /* load the private key from file - last arg is bool if key in file (true) or is string (false) */
            $objKey->loadKey($ruta_firma, TRUE);

            /* Sign the message - also signs appropiate WS-Security items */
            $objWSSE->signSoapDoc($objKey, $options);

            /* Add certificate (BinarySecurityToken) to the message */
            $token = $objWSSE->addBinaryToken(file_get_contents($ruta_firma));

            /* Attach pointer to Signature */
            $objWSSE->attachTokentoSig($token);

            $objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
            $objKey->generateSessionKey();

            $siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
            $siteKey->loadKey(storage_path('app/certificado/13254846-3.cer'), true, true);

            $options = array("KeyInfo" => array("X509SubjectKeyIdentifier" => true));

            $this->body = $doc->saveXML();

            return (object)[
                'status'=> true,
            ];
        }
        catch (\Exception $e) {
            return (object)[
                'status'=> false,
                'error' => $e->getMessage(),
            ];
        }
    }

    // envio de datos
    public function send()
    {
        try {
            // la seteoen una variable global, por si en algun momento se necesita hacer algo adicional
            $this->curl = curl_init();

            // Fusiono datos adicionales al config
            //lo hago de esta forma por sui el usuario modifico los datos en orden incorreto
            $config = [
                CURLOPT_URL => $this->url,
                CURLOPT_HTTPHEADER => $this->head,
                CURLOPT_POSTFIELDS => $this->body,
            ];
            // setea las config del usuario
            $this->setConfig($config, true);
            // se setea las configuraciones  al curl
            curl_setopt_array($this->curl, $this->config);
            // ejecuta el curl
            $this->response = curl_exec($this->curl);
            // verfica errores
            if( curl_error($this->curl) ) throw new \Exception( curl_error($this->curl));
            // verficia uin error de validacion u otro
            $error = $this->extract('<s:Fault>');
            if( $error->status && count($error->result) > 0 ){
                $mensaje =  $this->extract('<Message>');
                // verifica si existe error de otro tipo
                $mensaje = $mensaje->status && count($error->result) > 0 ? $mensaje->result[0] : 'Existe un error en la peticion, verifique la respuesta';

                return $temp_response = new TempResponse($this->response, $this->body, false, $mensaje);
            };
            // estructura para la respuesta
            $temp_response = new TempResponse($this->response, $this->body, true);

            return $temp_response;
        }
        catch (\Exception $e) {
            $temp_response = new TempResponse($this->response, $this->body, false, $e->getMessage() );

            return $temp_response;
        }
    }

    // permite extraer valores entre los tags
    public function extract($tags)
    {
        try {
            $result = [];
            $text = (string )$this->response;

            if( is_array($tags) ){
                foreach ($tags as $key => $tag) {
                    $pos_ini = mb_strpos($text, $tag) ? mb_strpos($text, $tag)+strlen($tags) : null;
                    $end = substr_replace($tag, '/',1,0);
                    $pos_fin = mb_strpos($text, $end) ? mb_strpos($text, $end) - $pos_ini : null;
                    if($pos_ini && $pos_fin){
                        $result[] = trim(substr($text, $pos_ini, $pos_fin-1));
                    }
                }
            }
            else{
                $pos_ini = mb_strpos($text, $tags) ? mb_strpos($text, $tags)+strlen($tags) : null;
                $end = substr_replace($tags, '/',1,0);
                $pos_fin = mb_strpos($text, $end) ? mb_strpos($text, $end) - $pos_ini : null;

                if($pos_ini && $pos_fin){
                    $result[] = trim(substr($text, $pos_ini,$pos_fin));
                }
            }

            return (object) [
                'status'=> true,
                'result' => $result,
            ];
        }
        catch (\Exception $e) {
            return (object) [
                'status'=> false,
                'error' => $e->getMessage().' : '.$e->getLine(),
            ];
        }
    }
}

// clase para generar los responses de la peticion
class TempResponse
{
    function __construct ($response , $body , $status , $error = null)
    {
        $this->status =  $status;
        $this->response = $response;
        $this->error =$error;
        $this->body = $body;
    }

    function __call ($method, $args)
    {
        if (isset($this->$method)) {
            $func = $this->$method;

            return call_user_func_array($func, $args);
        }
    }

    // registro emn cualquier tabla cualquier data
    public function respaldoDB( $datos, $tabla = 'tbl_finanzas_defontana_xml', $create_at = true )
    {
        try {
            if ($create_at) {
                $datos = array_merge($datos,['created_at' => date('y-m-d h:i:s') ]);
            }

            DB::table($tabla)->insert($datos);

            return (object) [
                'status'=> true,
            ];
        }
        catch (\Exception $e) {
            return (object) [
                'status'=> false,
                'error' => $e->getMessage().' : '.$e->getLine()
            ];
        }
    }

    public function generarFILE( $ruta_envio = null, $ruta_recepcion = null, $only_put = false )
    {
        try {
            if($this->body){
                Storage::disk('public')->put($ruta_envio, $this->body);
            }
            if($this->response){
                Storage::disk('public')->put($ruta_recepcion, $this->response);
            }

            return (object) [
                'status'=> true,
            ];
        }
        catch (\Exception $e) {
            return (object) [
                'status'=> false,
                'error' => $e->getMessage().' : '.$e->getLine(),
            ];
        }
    }
}
