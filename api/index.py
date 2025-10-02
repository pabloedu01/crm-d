from flask import Flask, request, jsonify, session, render_template_string
import pymongo
import bcrypt
from datetime import datetime
from bson.objectid import ObjectId
import secrets
import base64
import json

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua-chave-secreta-muito-forte-aqui'

# Configuração do seu domínio
RP_ID = "crm-d-sigma.vercel.app"  # Mude para seu domínio em produção
RP_NAME = "Minha Aplicação"
ORIGIN = "https://crm-d-sigma.vercel.app"  # Mude para https://seudominio.com em produção

# Conexão MongoDB
client = pymongo.MongoClient('mongodb+srv://opabloedu_db_user:IQuB0oSfjSsyrr23@tutudo.ujpkfrp.mongodb.net/?retryWrites=true&w=majority&appName=Tutudo')
db = client['minha_aplicacao']
users_collection = db['users']
credentials_collection = db['credentials']

# ============ UTILITÁRIOS ============

def base64url_to_bytes(base64url_string):
    """Converter base64url para bytes"""
    # Adicionar padding se necessário
    padding = 4 - (len(base64url_string) % 4)
    if padding != 4:
        base64url_string += '=' * padding

    # Substituir caracteres URL-safe
    base64_string = base64url_string.replace('-', '+').replace('_', '/')
    return base64.b64decode(base64_string)

def bytes_to_base64url(data):
    """Converter bytes para base64url"""
    return base64.b64encode(data).decode('utf-8').replace('+', '-').replace('/', '_').rstrip('=')

# ============ ROTAS DE REGISTRO ============

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """Registrar novo usuário (tradicional)"""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Todos os campos são obrigatórios'}), 400

    # Verificar se usuário já existe
    if users_collection.find_one({'username': username}):
        return jsonify({'error': 'Username já existe'}), 409

    # Hash da senha
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Inserir usuário
    user_doc = {
        'username': username,
        'email': email,
        'password_hash': password_hash,
        'user_id': secrets.token_urlsafe(32),  # ID único para WebAuthn
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }

    result = users_collection.insert_one(user_doc)

    # Criar sessão
    session['user_id'] = str(result.inserted_id)
    session['username'] = username
    session['logged_in'] = True

    return jsonify({
        'status': 'success',
        'message': 'Usuário criado com sucesso',
        'user_id': str(result.inserted_id)
    }), 201

# ============ PASSKEY REGISTRATION ============

@app.route('/api/passkey/register/start', methods=['POST'])
def start_passkey_registration():
    """Iniciar registro de passkey (Face ID, Touch ID, Windows Hello)"""

    # Verificar se usuário está logado
    if not session.get('logged_in'):
        return jsonify({'error': 'Usuário não está logado'}), 401

    # Buscar usuário
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404

    # Buscar credenciais existentes
    existing_credentials = list(credentials_collection.find({'user_id': str(user['_id'])}))

    # Preparar lista de credenciais existentes para exclusão
    exclude_credentials = []
    for cred in existing_credentials:
        try:
            credential_id_bytes = base64url_to_bytes(cred['credential_id'])
            exclude_credentials.append(PublicKeyCredentialDescriptor(id=credential_id_bytes))
        except:
            continue

    # Gerar opções de registro
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user['user_id'].encode(),
        user_name=user['username'],
        user_display_name=user.get('email', user['username']),
        exclude_credentials=exclude_credentials if exclude_credentials else None,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,  # Dispositivo local
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ]
    )

    # Salvar challenge na sessão
    session['current_challenge'] = bytes_to_base64url(options.challenge)

    # Converter para formato compatível com webauthn-json
    options_dict = json.loads(options_to_json(options))

    return jsonify(options_dict)

@app.route('/api/passkey/register/finish', methods=['POST'])
def finish_passkey_registration():
    """Finalizar registro de passkey"""

    if not session.get('logged_in'):
        return jsonify({'error': 'Usuário não está logado'}), 401

    if 'current_challenge' not in session:
        return jsonify({'error': 'Challenge não encontrado'}), 400

    data = request.get_json()
    credential = data.get('credential')

    if not credential:
        return jsonify({'error': 'Credencial não fornecida'}), 400

    try:
        # Converter challenge de volta para bytes
        challenge_bytes = base64url_to_bytes(session['current_challenge'])

        # Verificar resposta de registro
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge_bytes,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )

        # Buscar usuário
        user = users_collection.find_one({'_id': ObjectId(session['user_id'])})

        # Salvar credencial no banco
        credential_doc = {
            'user_id': str(user['_id']),
            'credential_id': bytes_to_base64url(verification.credential_id),
            'public_key': bytes_to_base64url(verification.credential_public_key),
            'sign_count': verification.sign_count,
            'transports': credential.get('response', {}).get('transports', []),
            'device_name': data.get('device_name', 'Dispositivo desconhecido'),
            'created_at': datetime.utcnow()
        }

        credentials_collection.insert_one(credential_doc)

        # Limpar challenge
        session.pop('current_challenge', None)

        return jsonify({
            'status': 'success',
            'message': 'Passkey registrado com sucesso!',
            'verified': True
        })

    except Exception as e:
        return jsonify({'error': f'Erro ao verificar credencial: {str(e)}'}), 400

# ============ PASSKEY AUTHENTICATION ============

@app.route('/api/passkey/login/start', methods=['POST'])
def start_passkey_login():
    """Iniciar login com passkey"""

    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username é obrigatório'}), 400

    # Buscar usuário
    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404

    # Buscar credenciais do usuário
    user_credentials = list(credentials_collection.find({'user_id': str(user['_id'])}))

    if not user_credentials:
        return jsonify({'error': 'Nenhuma passkey registrada para este usuário'}), 404

    # Preparar lista de credenciais permitidas
    allow_credentials = []
    for cred in user_credentials:
        try:
            credential_id_bytes = base64url_to_bytes(cred['credential_id'])
            allow_credentials.append(PublicKeyCredentialDescriptor(id=credential_id_bytes))
        except:
            continue

    # Gerar opções de autenticação
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED
    )

    # Salvar dados na sessão
    session['current_challenge'] = bytes_to_base64url(options.challenge)
    session['temp_username'] = username
    session['temp_user_id'] = str(user['_id'])

    # Converter para formato compatível
    options_dict = json.loads(options_to_json(options))

    return jsonify(options_dict)

@app.route('/api/passkey/login/finish', methods=['POST'])
def finish_passkey_login():
    """Finalizar login com passkey"""

    if 'current_challenge' not in session or 'temp_user_id' not in session:
        return jsonify({'error': 'Sessão inválida'}), 400

    data = request.get_json()
    credential = data.get('credential')

    if not credential:
        return jsonify({'error': 'Credencial não fornecida'}), 400

    try:
        # Buscar credencial salva
        credential_id = credential['id']
        stored_credential = credentials_collection.find_one({
            'user_id': session['temp_user_id'],
            'credential_id': credential_id
        })

        if not stored_credential:
            return jsonify({'error': 'Credencial não encontrada'}), 404

        # Converter dados
        challenge_bytes = base64url_to_bytes(session['current_challenge'])
        public_key_bytes = base64url_to_bytes(stored_credential['public_key'])

        # Verificar autenticação
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge_bytes,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=public_key_bytes,
            credential_current_sign_count=stored_credential['sign_count']
        )

        # Atualizar contador de assinaturas
        credentials_collection.update_one(
            {'_id': stored_credential['_id']},
            {'$set': {'sign_count': verification.new_sign_count}}
        )

        # Buscar usuário
        user = users_collection.find_one({'_id': ObjectId(session['temp_user_id'])})

        # Criar sessão
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['logged_in'] = True

        # Limpar dados temporários
        session.pop('current_challenge', None)
        session.pop('temp_username', None)
        session.pop('temp_user_id', None)

        return jsonify({
            'status': 'success',
            'message': 'Login com passkey realizado com sucesso!',
            'user_id': str(user['_id']),
            'username': user['username']
        })

    except Exception as e:
        return jsonify({'error': f'Erro ao verificar autenticação: {str(e)}'}), 400

# ============ OUTRAS ROTAS ============

@app.route('/api/passkey/list', methods=['GET'])
def list_passkeys():
    if not session.get('logged_in'):
        return jsonify({'error': 'Usuário não está logado'}), 401

    credentials = list(credentials_collection.find(
        {'user_id': session['user_id']},
        {'_id': 0, 'public_key': 0, 'user_id': 0}
    ))

    return jsonify({'status': 'success', 'credentials': credentials})

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username e senha são obrigatórios'}), 400

    user = users_collection.find_one({'username': username})

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
        return jsonify({'error': 'Credenciais inválidas'}), 401

    session['user_id'] = str(user['_id'])
    session['username'] = user['username']
    session['logged_in'] = True

    return jsonify({
        'status': 'success',
        'message': 'Login realizado com sucesso',
        'user_id': str(user['_id']),
        'username': user['username']
    }), 200

@app.route('/api/auth/logout', methods=['POST'])
def logout_user():
    session.clear()
    return jsonify({'status': 'success', 'message': 'Logout realizado'})

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    if session.get('logged_in'):
        passkey_count = credentials_collection.count_documents({'user_id': session['user_id']})
        return jsonify({
            'logged_in': True,
            'user_id': session['user_id'],
            'username': session['username'],
            'passkeys_count': passkey_count
        })
    return jsonify({'logged_in': False})

@app.route('/')
def home():
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Autenticação com Passkeys</title>
    <meta charset="utf-8">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px; 
        }
        button { 
            margin: 5px; 
            padding: 10px 20px; 
            cursor: pointer; 
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
        }
        button:hover { background: #0056b3; }
        .section { 
            border: 1px solid #ccc; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 8px;
        }
        input { 
            padding: 8px; 
            margin: 5px; 
            width: 200px; 
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        .success { color: green; font-weight: bold; }
        .error { color: red; font-weight: bold; }
        .info { 
            background: #e7f3ff; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }
        pre { 
            background: #f8f9fa; 
            padding: 10px; 
            border-radius: 4px; 
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <h1>🔐 Autenticação com Passkeys</h1>

    <div class="info">
        <strong>📱 Dispositivos Suportados:</strong><br>
        • Windows Hello (Face, Fingerprint, PIN)<br>
        • iPhone/iPad (Face ID, Touch ID)<br>
        • Android (Fingerprint, Face Unlock)<br>
        • Mac (Touch ID, Face ID)
    </div>

    <div class="section">
        <h2>1. Registrar Usuário</h2>
        <input type="text" id="reg_username" placeholder="Username">
        <input type="email" id="reg_email" placeholder="Email">
        <input type="password" id="reg_password" placeholder="Senha">
        <button onclick="registerUser()">Registrar</button>
    </div>

    <div class="section">
        <h2>2. Login com Senha</h2>
        <input type="text" id="login_username" placeholder="Username">
        <input type="password" id="login_password" placeholder="Senha">
        <button onclick="loginUser()">Login</button>
    </div>

    <div class="section">
        <h2>3. Registrar Passkey</h2>
        <button onclick="registerPasskey()">📱 Registrar Passkey</button>
        <p><small>Você precisa estar logado primeiro</small></p>
    </div>

    <div class="section">
        <h2>4. Login com Passkey</h2>
        <input type="text" id="passkey_username" placeholder="Username">
        <button onclick="loginWithPasskey()">🔑 Login com Passkey</button>
    </div>

    <div class="section">
        <h2>Status</h2>
        <button onclick="checkStatus()">Verificar Status</button>
        <button onclick="logout()">Logout</button>
        <div id="status"></div>
    </div>

    <div id="message"></div>

    <script>
        function showMessage(msg, isError = false) {
            document.getElementById('message').innerHTML = 
                `<p class="${isError ? 'error' : 'success'}">${msg}</p>`;
        }

        function base64urlToBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const padLen = (4 - (base64.length % 4)) % 4;
            const padded = base64.padEnd(base64.length + padLen, '=');
            const binary = atob(padded);
            const buffer = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                buffer[i] = binary.charCodeAt(i);
            }
            return buffer;
        }

        function bufferToBase64url(buffer) {
            const binary = String.fromCharCode(...new Uint8Array(buffer));
            const base64 = btoa(binary);
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        function convertCredentialCreationOptions(options) {
            options.challenge = base64urlToBuffer(options.challenge);
            options.user.id = base64urlToBuffer(options.user.id);

            if (options.excludeCredentials) {
                options.excludeCredentials = options.excludeCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id)
                }));
            }

            return options;
        }

        function convertCredentialRequestOptions(options) {
            options.challenge = base64urlToBuffer(options.challenge);

            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id)
                }));
            }

            return options;
        }

        function convertCredentialResponse(credential) {
            const response = {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                response: {},
                type: credential.type
            };

            if (credential.response.attestationObject) {
                response.response = {
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64url(credential.response.attestationObject)
                };
            } else {
                response.response = {
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                    signature: bufferToBase64url(credential.response.signature),
                    userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
                };
            }

            return response;
        }

        async function registerUser() {
            const data = {
                username: document.getElementById('reg_username').value,
                email: document.getElementById('reg_email').value,
                password: document.getElementById('reg_password').value
            };

            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });

                const result = await response.json();
                showMessage(result.message || result.error, !response.ok);
            } catch (error) {
                showMessage('Erro: ' + error.message, true);
            }
        }

        async function loginUser() {
            const data = {
                username: document.getElementById('login_username').value,
                password: document.getElementById('login_password').value
            };

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });

                const result = await response.json();
                showMessage(result.message || result.error, !response.ok);
            } catch (error) {
                showMessage('Erro: ' + error.message, true);
            }
        }

        async function registerPasskey() {
            try {
                const startResponse = await fetch('/api/passkey/register/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });

                if (!startResponse.ok) {
                    const error = await startResponse.json();
                    showMessage(error.error, true);
                    return;
                }

                const options = await startResponse.json();
                const convertedOptions = convertCredentialCreationOptions(options);

                const credential = await navigator.credentials.create({ 
                    publicKey: convertedOptions 
                });

                const convertedCredential = convertCredentialResponse(credential);

                const finishResponse = await fetch('/api/passkey/register/finish', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ credential: convertedCredential })
                });

                const result = await finishResponse.json();
                showMessage(result.message || result.error, !finishResponse.ok);

            } catch (error) {
                showMessage('Erro: ' + error.message, true);
            }
        }

        async function loginWithPasskey() {
            try {
                const username = document.getElementById('passkey_username').value;

                const startResponse = await fetch('/api/passkey/login/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username })
                });

                if (!startResponse.ok) {
                    const error = await startResponse.json();
                    showMessage(error.error, true);
                    return;
                }

                const options = await startResponse.json();
                const convertedOptions = convertCredentialRequestOptions(options);

                const credential = await navigator.credentials.get({ 
                    publicKey: convertedOptions 
                });

                const convertedCredential = convertCredentialResponse(credential);

                const finishResponse = await fetch('/api/passkey/login/finish', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ credential: convertedCredential })
                });

                const result = await finishResponse.json();
                showMessage(result.message || result.error, !finishResponse.ok);

            } catch (error) {
                showMessage('Erro: ' + error.message, true);
            }
        }

        async function checkStatus() {
            try {
                const response = await fetch('/api/auth/status');
                const result = await response.json();
                document.getElementById('status').innerHTML = 
                    '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
            } catch (error) {
                showMessage('Erro: ' + error.message, true);
            }
        }

        async function logout() {
            try {
                await fetch('/api/auth/logout', { method: 'POST' });
                showMessage('Logout realizado');
                checkStatus();
            } catch (error) {
                showMessage('Erro: ' + error.message, true);
            }
        }

        // Verificar suporte a WebAuthn
        if (!window.PublicKeyCredential) {
            showMessage('⚠️ Seu navegador não suporta WebAuthn/Passkeys', true);
        } else {
            showMessage('✅ WebAuthn suportado! Você pode usar passkeys.');
        }
    </script>
</body>
</html>
    """)

if __name__ == '__main__':
    print("🚀 Iniciando aplicação Flask com Passkeys (CORRIGIDA)...")
    print("📱 Acesse http://localhost:5000 para testar")
    print("⚠️  Para produção, use HTTPS e configure RP_ID e ORIGIN corretamente")
    app.run(debug=True, port=5000, host='0.0.0.0')
