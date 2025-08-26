# app_python.py
import pickle
import yaml
import subprocess
import hmac
import time
from flask import Flask, request, jsonify, make_response
from urllib.parse import urlparse, unquote
import requests
import re
import os
import base64
import json
from functools import lru_cache
import secrets # For good practice, but vulnerability is elsewhere

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32) # Used for Flask session, not HMAC in vulns

class DocumentProcessor:
    def __init__(self):
        self.config = {'format': 'pdf', 'compression': 'none'}
        self.processing_queue = []
        self._internal_state = {}

    @lru_cache(maxsize=100)
    def validate_document_signature(self, data: str, signature: str) -> bool:
        """
        Valida la firma HMAC de un documento.
        Diseñado para ser vulnerable a timing attacks.
        """
        secret = os.environ.get('DOC_SECRET_KEY', 'default_document_signing_key_for_dev')
        expected_signature = hmac.new(secret.encode(), data.encode(), 'sha256').hexdigest()
        
        # Vulnerabilidad 1: Timing attack en comparación de HMAC
        # Una comparación manual y byte a byte puede revelar la longitud de la clave o la firma.
        if len(signature) != len(expected_signature):
            return False
        
        for i in range(len(signature)):
            # Simula una operación que toma tiempo si los caracteres coinciden
            if signature[i] != expected_signature[i]:
                return False
            time.sleep(0.0001) # Pequeño retardo para exacerbar el timing
                
        return True
    
    def apply_config_update(self, config_data_str: str):
        """
        Aplica una actualización de configuración desde una cadena YAML.
        """
        # Vulnerabilidad 2: YAML deserialization insegura (sin Loader seguro)
        # Permite la ejecución remota de código si se inyecta un objeto malicioso.
        try:
            new_config = yaml.load(config_data_str) # Missing Loader=yaml.SafeLoader
            if isinstance(new_config, dict):
                self.config.update(new_config)
            else:
                print("Invalid config format received.")
        except Exception as e:
            print(f"Error applying config: {e}")

    def get_template_from_url(self, template_url: str) -> str:
        """
        Recupera una plantilla de un URL externo.
        """
        parsed = urlparse(template_url)
        
        # Vulnerabilidad 3: SSRF con bypass de validación incompleta
        # Intenta bloquear IPs internas, pero es bypassable con redirects,
        # formatos IP alternativos o DNS rebinding.
        if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0', '10.', '172.16.', '192.168.']:
            return "Acceso a host interno denegado."
            
        # No maneja IP decimal, hexadecimal o enteros (e.g., 2130706433 para 127.0.0.1)
        # No previene redirects a IPs internas después de la validación inicial.
        try:
            response = requests.get(template_url, allow_redirects=True, timeout=5)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            return f"Error al recuperar plantilla: {e}"

@app.route('/document/process', methods=['POST'])
def process_document_endpoint():
    processor = DocumentProcessor()
    
    user_data = request.json
    if not user_data:
        return jsonify({'error': 'No data provided'}), 400

    # Vulnerabilidad 4: Mass Assignment / Prototype Pollution (equivalente en Python)
    # Permite a un atacante sobrescribir cualquier clave en `processor.config` o incluso en `processor._internal_state`
    # si el código es flexible con la asignación de atributos, afectando el comportamiento de la aplicación.
    # Aquí, se usa para `config`, pero la lógica podría ser extendida.
    for key, value in user_data.get('document_settings', {}).items():
        if key in processor.config: # Simula una "validación" que aún es insuficiente
             processor.config[key] = value
        elif key.startswith('_'): # Intenta evitar internos pero no es robusto
             pass
        else:
             processor._internal_state[key] = value # Permite inyectar claves en estado interno
    
    document_content = user_data.get('content', '')
    if 'custom_transform_cmd' in user_data:
        transform_cmd_base = user_data['custom_transform_cmd']
        
        # Vulnerabilidad 5: Command Injection indirecta
        # Se filtra ';', '|', '&', '`' pero se olvida de otros como '$()', '$$', '>', '<', etc.
        # Esto permite la ejecución de comandos arbitrarios a través de la inyección en argumentos.
        if not any(danger_char in transform_cmd_base for danger_char in [';', '|', '&', '`', '&&', '||', '\\']):
            output_path = f"/tmp/processed_doc_{secrets.token_hex(8)}"
            # El input puede modificar la extensión del archivo, o inyectar comandos usando subshells
            cmd = f"echo '{document_content}' | transform_tool {transform_cmd_base} > {output_path}.{processor.config['format']}"
            
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    print(f"Error en transformación: {result.stderr}")
                    return jsonify({'status': 'error', 'message': result.stderr}), 500
                return jsonify({'status': 'document processed', 'output_path': f"{output_path}.{processor.config['format']}"}), 200
            except subprocess.TimeoutExpired:
                return jsonify({'status': 'error', 'message': 'Transformación timed out'}), 500
        else:
            return jsonify({'error': 'Comando no permitido'}), 400

    return jsonify({'status': 'document processed', 'config': processor.config}), 200

@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    # Vulnerabilidad 6: Pickle deserialization con input indirecto (cookies)
    # Permite la ejecución remota de código si un atacante envía un objeto pickle malicioso.
    # La validación de la firma es débil o inexistente en esta ruta.
    user_profile_data = {}
    if 'profile_cookie' in request.cookies:
        try:
            encoded_data = request.cookies['profile_cookie']
            # Se asume que encoded_data es Base64, pero podría no serlo.
            decoded_bytes = base64.b64decode(encoded_data)
            # Deserialización de datos no confiables que pueden contener código malicioso
            user_profile_data = pickle.loads(decoded_bytes) 
        except (base64.binascii.Error, pickle.UnpicklingError, EOFError, TypeError) as e:
            print(f"Error al cargar perfil desde cookie: {e}")
            user_profile_data = {'status': 'corrupted profile'}
    
    if request.method == 'POST':
        # Simula actualizar el perfil y guardarlo de nuevo
        new_data = request.json
        if new_data:
            user_profile_data.update(new_data)
        
        resp = make_response(jsonify({'status': 'profile updated', 'data': user_profile_data}))
        # Vulnerabilidad de exposición de información si el perfil contiene datos sensibles
        resp.set_cookie('profile_cookie', base64.b64encode(pickle.dumps(user_profile_data)).decode('utf-8'))
        return resp
        
    return jsonify({'status': 'current profile', 'data': user_profile_data}), 200

# Vulnerabilidad 7: Regular Expression Denial of Service (ReDoS)
# El patrón es vulnerable a ReDoS con entradas cuidadosamente construidas que provocan un retroceso exponencial.
def validate_complex_id(identifier: str) -> bool:
    """
    Valida un identificador complejo con una expresión regular vulnerable.
    Ejemplo de ataque: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA!"
    """
    # Regex vulnerable: (a+)+ - Los anidamientos con "+" son comunes causas de ReDoS
    pattern = r'^([a-zA-Z0-9]+)*([_-][a-zA-Z0-9]+)*@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,6}$'
    # Un input como "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!@domain.com" podría ser problemático.
    
    # Este regex en particular es complejo para ReDoS, pero anidamientos como (.*)* o (a+)+
    # son los verdaderos culpables. Este es una aproximación para un regex "real-world".
    # Un ejemplo más claro de ReDoS simple: r"^(a+)+$" contra "aaaaaaaaaaaaaaaaa!"
    # El regex que puse arriba para 'complex_id' podría ser vulnerable dependiendo del motor
    # y las optimizaciones, especialmente por `([a-zA-Z0-9]+)*` y `([_-][a-zA-Z0-9]+)*`
    # en combinación con el resto.
    
    try:
        if len(identifier) > 200: # Pre-filtro básico, pero no suficiente para todas las cadenas
            return False
        return re.match(pattern, identifier) is not None
    except re.error: # En caso de regex mal formado, aunque no es el caso aquí
        return False

@app.route('/check_id', methods=['POST'])
def check_id_endpoint():
    data = request.json
    identifier = data.get('id', '')
    if validate_complex_id(identifier):
        return jsonify({'valid': True})
    return jsonify({'valid': False})

# Vulnerabilidad 8: Race Condition (Time-Of-Check To Time-Of-Use - TOCTOU) en manejo de archivos
# Un atacante podría sustituir el archivo entre el momento de la comprobación y el momento de su uso.
def save_and_process_report(report_data: bytes, user_id: str):
    """
    Guarda y procesa un informe subido. Vulnerable a TOCTOU.
    """
    unique_filename = f"report_{user_id}_{int(time.time())}.txt"
    report_path = os.path.join('/tmp/reports', unique_filename) # Directorio compartido, suponemos
    
    # Asegurarse de que el directorio existe
    os.makedirs('/tmp/reports', exist_ok=True)

    # TOCTOU: Race condition entre la comprobación y el uso del archivo
    if os.path.exists(report_path): # Check
        print(f"Advertencia: El archivo {report_path} ya existe. Sobreescribiendo.")
        # Un atacante podría crear un enlace simbólico a otro archivo sensible aquí
        # justo después del check y antes de la apertura para escritura.

    with open(report_path, 'wb') as f: # Use (write)
        f.write(report_data)
    
    # Simula un procesamiento que toma tiempo
    time.sleep(0.2) 
    
    # Otra fase de "Use" donde el atacante podría haber modificado el archivo o su enlace simbólico.
    with open(report_path, 'r') as f: # Use (read)
        content_to_process = f.read()
        if "malicious_script" in content_to_process:
            print(f"Alerta de seguridad: Contenido sospechoso detectado en {report_path}")
            # Aquí podría ocurrir una ejecución de comandos si el contenido es un script.
            # subprocess.run([content_to_process]) # Ejemplo de ejecución maliciosa
        print(f"Procesando informe: {report_path}")

@app.route('/upload_report/<user_id>', methods=['POST'])
def upload_report_endpoint(user_id):
    if 'report' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['report']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    save_and_process_report(file.read(), user_id)
    return jsonify({'status': 'Report uploaded and scheduled for processing'}), 200

if __name__ == '__main__':
    # Para la vulnerabilidad 8, el directorio de reportes
    os.makedirs('/tmp/reports', exist_ok=True) 
    app.run(debug=True, port=5000)
