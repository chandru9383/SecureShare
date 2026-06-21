from flask import Flask, render_template, request, jsonify, send_file, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import os
import io
from crypto_utils import encrypt_secret, decrypt_secret

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secrets.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Secret(db.Model):
    __tablename__ = 'secrets'
    id = db.Column(db.String(8), primary_key=True)
    ciphertext = db.Column(db.Text, nullable=False)
    views_left = db.Column(db.Integer, default=1)
    has_password = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_expired(self):
        return self.expires_at and self.expires_at < datetime.utcnow()

    def is_burned(self):
        return self.views_left <= 0

with app.app_context():
    db.create_all()

def cleanup_expired():
    now = datetime.utcnow()
    expired = Secret.query.filter(Secret.expires_at < now).all()
    for s in expired:
        db.session.delete(s)
    db.session.commit()

@app.before_request
def before_request():
    cleanup_expired()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create', methods=['POST'])
def create_secret():
    try:
        plaintext = request.form.get('text', '').strip()
        password = request.form.get('password', '')
        views = int(request.form.get('views', 1))
        expiry_hours = request.form.get('expiry', 'never')
    except ValueError:
        return jsonify({'error': 'Invalid input'}), 400

    if not plaintext:
        return jsonify({'error': 'Secret cannot be empty'}), 400

    ciphertext = encrypt_secret(plaintext, password)
    secret_id = uuid.uuid4().hex[:8]

    expires_at = None
    if expiry_hours != 'never':
        hours = int(expiry_hours)
        expires_at = datetime.utcnow() + timedelta(hours=hours)

    secret = Secret(
        id=secret_id,
        ciphertext=ciphertext,
        views_left=views,
        has_password=bool(password),
        expires_at=expires_at
    )
    db.session.add(secret)
    db.session.commit()

    link = url_for('view_secret_page', secret_id=secret_id, _external=True)

    return jsonify({
        'success': True,
        'link': link,
        'id': secret_id,
        'views': views,
        'expires': expiry_hours if expiry_hours != 'never' else 'Never'
    })

@app.route('/qrcode/<secret_id>')
def qrcode_image(secret_id):
    try:
        import qrcode
    except ImportError:
        return jsonify({'error': 'QR code generator is unavailable'}), 501

    target_url = url_for('view_secret_page', secret_id=secret_id, _external=True)
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(target_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')

    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)

    return send_file(buffer, mimetype='image/png')

@app.route('/s/<secret_id>')
def view_secret_page(secret_id):
    secret = Secret.query.get(secret_id)

    if not secret or secret.is_expired() or secret.is_burned():
        if secret:
            db.session.delete(secret)
            db.session.commit()
        return render_template('burned.html', message="This secret no longer exists."), 404

    return render_template('view.html', secret_id=secret_id, has_password=secret.has_password)

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
        plaintext = decrypt_secret(secret.ciphertext, password)
    except ValueError:
        return jsonify({'error': 'Incorrect password'}), 401

    secret.views_left -= 1
    burned = secret.views_left <= 0

    if burned:
        db.session.delete(secret)
        db.session.commit()
    else:
        db.session.commit()

    return jsonify({
        'success': True,
        'text': plaintext,
        'burned': burned,
        'views_left': secret.views_left if not burned else 0
    })

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', message="This page does not exist."), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message="Something went wrong on our end."), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)