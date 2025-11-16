"""
Main Flask application - handles HTTP routes and session management
"""
from flask import Flask, render_template, request, jsonify, session
from webauthn import options_to_json
from config import Config
from webauthn_service import WebAuthnService
import traceback


def create_app(config_class=Config):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize WebAuthn service
    webauthn_service = WebAuthnService(
        rp_id=app.config['RP_ID'],
        rp_name=app.config['RP_NAME'],
        origin=app.config['ORIGIN']
    )
    
    @app.route('/')
    def index():
        """Render the main page"""
        return render_template('index.html')
    
    @app.route('/register/start', methods=['POST'])
    def register_start():
        """Start the registration process"""
        try:
            data = request.json
            username = data.get('username')
            
            if not username:
                return jsonify({'error': 'Username required'}), 400
            
            # Generate registration options
            options, challenge_hex = webauthn_service.generate_registration_options(username)
            
            # Store challenge and username in session
            session['registration_challenge'] = challenge_hex
            session['username'] = username
            
            return options_to_json(options)
            
        except Exception as e:
            print(f"Registration start error: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 400
    
    @app.route('/register/finish', methods=['POST'])
    def register_finish():
        """Complete the registration process"""
        try:
            username = session.get('username')
            challenge_hex = session.get('registration_challenge')
            
            if not username or not challenge_hex:
                return jsonify({'error': 'Session expired'}), 400
            
            # FIXED: Use request.json to get the parsed JSON data
            credential_data = request.json
            
            # Verify the registration
            success, message = webauthn_service.verify_registration(
                credential_json=credential_data,
                challenge_hex=challenge_hex,
                username=username
            )
            
            # Clear session data
            session.pop('registration_challenge', None)
            
            return jsonify({
                'verified': success,
                'message': message
            })
            
        except Exception as e:
            print(f"Registration finish error: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 400
    
    @app.route('/login/start', methods=['POST'])
    def login_start():
        """Start the authentication process"""
        try:
            data = request.json
            username = data.get('username')
            
            if not username:
                return jsonify({'error': 'Username required'}), 400
            
            # Generate authentication options
            options, challenge_hex = webauthn_service.generate_authentication_options(username)
            
            # Store challenge and username in session
            session['authentication_challenge'] = challenge_hex
            session['username'] = username
            
            return options_to_json(options)
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            print(f"Login start error: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 400
    
    @app.route('/login/finish', methods=['POST'])
    def login_finish():
        """Complete the authentication process"""
        try:
            challenge_hex = session.get('authentication_challenge')
            
            if not challenge_hex:
                return jsonify({'error': 'Session expired'}), 400
            
            # FIXED: Use request.json to get the parsed JSON data
            credential_data = request.json
            
            # Verify the authentication
            success, message, username = webauthn_service.verify_authentication(
                credential_json=credential_data,
                challenge_hex=challenge_hex
            )
            
            # Clear session data
            session.pop('authentication_challenge', None)
            
            return jsonify({
                'verified': success,
                'message': message,
                'username': username
            })
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            print(f"Login finish error: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 400
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(
        debug=app.config['DEBUG'],
        host='localhost',
        port=app.config['PORT']
    )
