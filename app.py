import os
import uuid
from datetime import datetime, timedelta
from io import BytesIO

from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from crypto_utils import encrypt_data, decrypt_data

# ─── Initialize Flask App ──────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())

# ✅ Use PostgreSQL (Supabase) – read from environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("DATABASE_URL environment variable not set!")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

db = SQLAlchemy(app)

# ─── Database Model ──────────────────────────────────────
class Secret(db.Model):
    __tablename__ = 'secrets'
    id = db.Column(db.String(8), primary_key=True)
    ciphertext = db.Column(db.Text, nullable=False)
    views_left = db.Column(db.Integer, default=1)
    has_password = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    filename = db.Column(db.String(255), nullable=True)
    content_type = db.Column(db.String(100), nullable=True)
    is_file = db.Column(db.Boolean, default=False)

    def is_expired(self):
        return self.expires_at and self.expires_at < datetime.utcnow()

    def is_burned(self):
        return self.views_left <= 0

# ─── Create Tables ──────────────────────────────────────
with app.app_context():
    db.create_all()

# ─── Cleanup expired secrets ────────────────────────────
def cleanup_expired():
    now = datetime.utcnow()
    expired = Secret.query.filter(Secret.expires_at < now).all()
    for s in expired:
        db.session.delete(s)
    db.session.commit()

@app.before_request
def before_request():
    cleanup_expired()

# ─── Routes ──────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create', methods=['POST'])
def create_secret():
    try:
        password = request.form.get('password', '')
        views = int(request.form.get('views', 1))
        expiry_hours = request.form.get('expiry', 'never')

        # Check for file or text
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            filename = file.filename
            content_type = file.content_type or 'application/octet-stream'
            data = file.read()
            is_file = True
        else:
            plaintext = request.form.get('text', '').strip()
            if not plaintext:
                return jsonify({'error': 'Please enter text or select a file'}), 400
            data = plaintext.encode('utf-8')
            filename = None
            content_type = 'text/plain'
            is_file = False

    except ValueError:
        return jsonify({'error': 'Invalid input'}), 400

    # Encrypt
    ciphertext = encrypt_data(data, password)
    secret_id = uuid.uuid4().hex[:8]

    # Expiry
    expires_at = None
    if expiry_hours != 'never':
        hours = int(expiry_hours)
        expires_at = datetime.utcnow() + timedelta(hours=hours)

    secret = Secret(
        id=secret_id,
        ciphertext=ciphertext,
        views_left=views,
        has_password=bool(password),
        expires_at=expires_at,
        filename=filename,
        content_type=content_type,
        is_file=is_file
    )
    db.session.add(secret)
    db.session.commit()

    link = request.host_url + 's/' + secret_id

    return jsonify({
        'success': True,
        'link': link,
        'id': secret_id,
        'views': views,
        'expires': expiry_hours if expiry_hours != 'never' else 'Never',
        'is_file': is_file,
        'filename': filename
    })

@app.route('/s/<secret_id>')
def view_secret_page(secret_id):
    secret = Secret.query.get(secret_id)
    if not secret or secret.is_expired() or secret.is_burned():
        if secret:
            db.session.delete(secret)
            db.session.commit()
        return render_template('burned.html', message="This secret no longer exists."), 404

    return render_template('view.html',
                           secret_id=secret_id,
                           has_password=secret.has_password,
                           is_file=secret.is_file,
                           filename=secret.filename)

@app.route('/s/<secret_id>/decrypt', methods=['POST'])
def decrypt_secret_route(secret_id):
    secret = Secret.query.get(secret_id)
    if not secret:
        return jsonify({'error': 'Secret not found'}), 404

    if secret.is_expired():
        db.session.delete(secret)
        db.session.commit()
        return jsonify({'error': 'Secret has expired'}), 410

    if secret.is_burned():
        db.session.delete(secret)
        db.session.commit()
        return jsonify({'error': 'Secret has already been destroyed'}), 410

    password = request.form.get('password', '')

    try:
        data = decrypt_data(secret.ciphertext, password)
    except ValueError:
        return jsonify({'error': 'Incorrect password'}), 401

    secret.views_left -= 1
    burned = secret.views_left <= 0

    if burned:
        db.session.delete(secret)
        db.session.commit()
    else:
        db.session.commit()

    # If it's a file, return as download
    if secret.is_file and secret.filename:
        return send_file(
            BytesIO(data),
            download_name=secret.filename,
            mimetype=secret.content_type or 'application/octet-stream',
            as_attachment=True
        )

    return jsonify({
        'success': True,
        'text': data.decode('utf-8'),
        'burned': burned,
        'views_left': secret.views_left if not burned else 0,
        'is_file': secret.is_file
    })

@app.errorhandler(404)
def not_found(error):
    return render_template('burned.html', message="This secret does not exist."), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('burned.html', message="Something went wrong on our end."), 500

# ─── For local testing ──────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)