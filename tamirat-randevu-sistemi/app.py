from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user as login_user_func, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from datetime import datetime
from flask_login import login_required
import re
from flask import session, redirect, url_for
import logging
from flask import jsonify
from sqlalchemy import func
from flask_socketio import SocketIO, emit, join_room,leave_room
from calendar import month_name
from sqlalchemy import extract
import eventlet
from sqlalchemy.engine import Engine
from sqlalchemy import event
import sqlite3


app = Flask(__name__)
app.config['SECRET_KEY'] = 'gelistirme_anahtari'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///teknoloji.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")



db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'  # Login gerekli sayfalarda buraya yönlendirme yapılacak




# MODELLER
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    ad = db.Column(db.String(50), nullable=False)
    soyad = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    tc = db.Column(db.String(11), unique=True, nullable=False)
    telefon = db.Column(db.String(11), unique=True, nullable=False)
    dogum_tarihi = db.Column(db.Date, nullable=False)
    cinsiyet = db.Column(db.String(10), nullable=False)
    konum = db.Column(db.String(50))
    sifre = db.Column(db.String(255), nullable=False)
    kayit_tarihi = db.Column(db.DateTime, default=datetime.utcnow)

    # Cascade ile randevu ve mesajların otomatik silinmesi
    appointments = db.relationship('Appointment', backref='user', lazy=True, cascade="all, delete-orphan")
    received_messages = db.relationship('Message', backref='user', lazy=True, cascade="all, delete-orphan")

    def get_id(self):
        return f"user-{self.id}"


class Technician(UserMixin, db.Model):
    __tablename__ = 'technicians'
    id = db.Column(db.Integer, primary_key=True)
    ad = db.Column(db.String(50), nullable=False)
    soyad = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    telefon = db.Column(db.String(11), unique=True, nullable=False)
    tc = db.Column(db.String(11), unique=True, nullable=False)
    dogum_tarihi = db.Column(db.Date, nullable=False)
    uzmanlik = db.Column(db.String(100), nullable=False)
    destek_modeli = db.Column(db.String(50), nullable=False)
    tecrube = db.Column(db.Integer, nullable=False)
    konum = db.Column(db.String(50))
    referans = db.Column(db.Text)
    ek_yetenekler = db.Column(db.Text)
    sifre = db.Column(db.String(255), nullable=False)
    kayit_tarihi = db.Column(db.DateTime, default=datetime.utcnow)
    onay = db.Column(db.Boolean, default=False)
    iptal = db.Column(db.Boolean, default=False)

    # Cascade ile ilişkili randevu ve mesajların silinmesi
    appointments = db.relationship('Appointment', backref='technician', lazy=True, cascade="all, delete-orphan")
    sent_messages = db.relationship('Message', backref='technician', lazy=True, cascade="all, delete-orphan")

    def get_id(self):
        return f"tech-{self.id}"


class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    technician_id = db.Column(db.Integer, db.ForeignKey('technicians.id', ondelete="SET NULL"), nullable=True)
    date = db.Column(db.Date, nullable=False)
    uzmanlik = db.Column(db.String(100), nullable=False)
    destek_modeli = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Beklemede')


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    technician_id = db.Column(db.Integer, db.ForeignKey('technicians.id', ondelete="CASCADE"), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender_type = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f'<Message {self.subject} from {self.sender_type} (tech:{self.technician_id}, user:{self.user_id})>'



class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    tc = db.Column(db.String(11), unique=True, nullable=False)
    ad = db.Column(db.String(50), nullable=False)
    soyad = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    sifre = db.Column(db.String(255), nullable=False)
    kayit_tarihi = db.Column(db.DateTime, default=datetime.utcnow)

    def get_id(self):
        return f"admin-{self.id}"


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    target_group = db.Column(db.String(20), nullable=False)  # 'tekniker' veya 'uye'


@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith("user-"):
        return db.session.get(User, int(user_id[5:]))
    elif user_id.startswith("tech-"):
        return db.session.get(Technician, int(user_id[5:]))
    elif user_id.startswith("admin-"):
        return db.session.get(Admin, int(user_id[6:]))

   

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

# Login ve Register seçim
@app.route('/login', methods=['POST'])
def choose_login():
    role = request.form.get('role')
    if role == "technician":
        return redirect(url_for('technician_login'))
    elif role == "user":
        return redirect(url_for('user_login'))
    flash('Lütfen bir kullanıcı türü seçiniz.', 'warning')
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def choose_register():
    role = request.form.get('role')
    if role == "technician":
        return redirect(url_for('register_technician'))
    elif role == "user":
        return redirect(url_for('register_user'))
    flash('Lütfen bir kullanıcı türü seçiniz.', 'warning')
    return redirect(url_for('index'))

# Kullanıcı Giriş
@app.route('/login_user', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        tc = request.form.get('tc')
        sifre = request.form.get('sifre')

        if not tc or not sifre:
            flash('Lütfen tüm alanları doldurun.', 'warning')
            return redirect(url_for('user_login'))

        user = User.query.filter_by(tc=tc).first()
        if user and check_password_hash(user.sifre, sifre):
            login_user_func(user)
            flash('Giriş başarılı!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Hatalı TC veya şifre!', 'danger')
            return redirect(url_for('user_login'))

    return render_template('login_user.html')


@app.route('/login_technician', methods=['GET', 'POST'])
def technician_login():
    if request.method == 'POST':
        tc = request.form.get('tc')
        sifre = request.form.get('sifre')

        tekniker = Technician.query.filter_by(tc=tc).first()
        if tekniker:
            if tekniker.iptal:
                flash('Tekniker hesabınız iptal edilmiştir. Sisteme giriş yapamazsınız.', 'danger')
                return redirect(url_for('technician_login'))

            if not tekniker.onay:
                flash('Tekniker hesabınız henüz onaylanmadı. Lütfen yönetici ile iletişime geçin.', 'warning')
                return redirect(url_for('technician_login'))

            if check_password_hash(tekniker.sifre, sifre):
                login_user_func(tekniker)
                flash('Tekniker girişi başarılı!', 'success')
                return redirect(url_for('technician_dashboard'))

        flash('Hatalı TC veya şifre!', 'danger')
        return redirect(url_for('technician_login'))

    return render_template('login_technician.html')



@app.route('/logout')
def logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('index'))

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    errors = {}
    form = {}

    if request.method == 'POST':
        # Form verileri al
        form['ad'] = request.form.get('ad', '').strip()
        form['soyad'] = request.form.get('soyad', '').strip()
        form['email'] = request.form.get('email', '').strip()
        form['tc'] = request.form.get('tc', '').strip()
        form['telefon'] = request.form.get('telefon', '').strip()
        form['dogumTarihi'] = request.form.get('dogumTarihi', '').strip()
        form['cinsiyet'] = request.form.get('cinsiyet', '').strip()
        form['konum'] = request.form.get('konum', '').strip()
        sifre = request.form.get('sifre', '')
        sifre_onay = request.form.get('sifreOnay', '')

        # Zorunlu alanlar kontrolü
        for field in ['ad', 'soyad', 'email', 'tc', 'telefon', 'dogumTarihi', 'cinsiyet', 'konum']:
            if not form[field]:
                errors[field] = 'Bu alan zorunludur.'

        # Şifre alanları kontrolü
        if not sifre:
            errors['sifre'] = 'Şifre alanı zorunludur.'
        if not sifre_onay:
            errors['sifreOnay'] = 'Şifre tekrar alanı zorunludur.'

        if sifre and sifre_onay and sifre != sifre_onay:
            errors['sifreOnay'] = 'Şifreler eşleşmiyor.'

        # TC Kimlik No kontrolü
        if form.get('tc') and (not form['tc'].isdigit() or len(form['tc']) != 11):
            errors['tc'] = 'TC Kimlik numarası 11 haneli ve rakamlardan oluşmalıdır.'

        # Telefon kontrolü
        if form.get('telefon') and (not form['telefon'].isdigit() or len(form['telefon']) != 11):
            errors['telefon'] = 'Telefon numarası 11 haneli ve rakamlardan oluşmalıdır.'

        # Email format kontrolü
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if form.get('email') and not re.match(email_regex, form['email']):
            errors['email'] = 'Geçerli bir email adresi giriniz.'

        # Email, TC veya telefon daha önce kayıtlı mı kontrol et
        if not errors.get('email') and not errors.get('tc') and not errors.get('telefon'):
            mevcut_kullanici = User.query.filter(
                or_(User.email == form['email'], User.tc == form['tc'], User.telefon == form['telefon'])
            ).first()
            mevcut_tekniker = Technician.query.filter(
                or_(Technician.email == form['email'], Technician.tc == form['tc'], Technician.telefon == form['telefon'])
            ).first()
            if mevcut_kullanici or mevcut_tekniker:
                errors['genel'] = 'Bu bilgilerle kullanıcı zaten var!'

        # Doğum tarihi parse ve yaş kontrol
        if form.get('dogumTarihi'):
            try:
                dogum_tarihi_obj = datetime.strptime(form['dogumTarihi'], '%Y-%m-%d')
                today = datetime.today()
                age = today.year - dogum_tarihi_obj.year - ((today.month, today.day) < (dogum_tarihi_obj.month, dogum_tarihi_obj.day))
                if age < 18:
                    errors['dogumTarihi'] = '18 yaşından küçükler kayıt olamaz.'
            except ValueError:
                errors['dogumTarihi'] = 'Doğum tarihi formatı hatalı.'

        # Hata varsa formu tekrar göster
        if errors:
            return render_template('register_user.html', form=form, errors=errors)

        # Şifreyi hashle
        sifre_hash = generate_password_hash(sifre)

        # Yeni kullanıcı oluştur
        yeni_user = User(
            ad=form['ad'],
            soyad=form['soyad'],
            email=form['email'],
            tc=form['tc'],
            telefon=form['telefon'],
            dogum_tarihi=dogum_tarihi_obj,
            cinsiyet=form['cinsiyet'],
            konum=form['konum'],
            sifre=sifre_hash
        )

        db.session.add(yeni_user)
        db.session.commit()

        flash('Kayıt başarılı!', 'success')
        return redirect(url_for('user_login'))

    # GET isteğinde boş form ile sayfa göster
    return render_template('register_user.html', form={}, errors={})




@app.route('/register_technician', methods=['GET', 'POST'])
def register_technician():
    errors = {}
    form = {}

    if request.method == 'POST':
        form = {
            'ad': request.form.get('ad', '').strip(),
            'soyad': request.form.get('soyad', '').strip(),
            'email': request.form.get('email', '').strip(),
            'telefon': request.form.get('telefon', '').strip(),
            'tc': request.form.get('tc', '').strip(),
            'dogumTarihi': request.form.get('dogumTarihi', '').strip(),
            'uzmanlik': request.form.get('uzmanlik', '').strip(),
            'destek_modeli': request.form.get('destek_modeli', '').strip(),
            'tecrube': request.form.get('tecrube', '').strip(),
            'konum': request.form.get('konum', '').strip(),
            'referans': request.form.get('referans', '').strip(),
            'ek_yetenekler': request.form.get('ek_yetenekler', '').strip(),
           
        }
        sifre = request.form.get('sifre', '')
        sifre_onay = request.form.get('sifreOnay', '')

        # Zorunlu alan kontrolü
        for alan in ['ad', 'soyad', 'email', 'telefon', 'tc', 'dogumTarihi', 'uzmanlik', 'destek_modeli', 'tecrube', 'konum']:
            if not form[alan]:
                errors[alan] = 'Bu alan zorunludur.'

        # Tecrübe sayısal mı?
        if form.get('tecrube') and not form['tecrube'].isdigit():
            errors['tecrube'] = 'Tecrübe yılı sayısal olmalıdır.'
        else:
            form['tecrube'] = int(form['tecrube']) if form.get('tecrube') else None

        # Şifreler eşleşiyor mu?
        if not sifre:
            errors['sifre'] = 'Şifre boş olamaz.'
        if sifre != sifre_onay:
            errors['sifreOnay'] = 'Şifreler eşleşmiyor.'

        # TC kontrolü
        if form.get('tc') and (not form['tc'].isdigit() or len(form['tc']) != 11):
            errors['tc'] = 'TC Kimlik numarası 11 haneli olmalıdır.'

        # Telefon kontrolü
        if form.get('telefon') and (not form['telefon'].isdigit() or len(form['telefon']) != 11):
            errors['telefon'] = 'Telefon numarası 11 haneli olmalıdır.'

        # Email regex kontrolü
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if form.get('email') and not re.match(email_regex, form['email']):
            errors['email'] = 'Geçerli bir email adresi giriniz.'

        # Doğum tarihi kontrolü ve yaş hesaplama
        if form.get('dogumTarihi'):
            try:
                dogum_tarihi_obj = datetime.strptime(form['dogumTarihi'], '%Y-%m-%d')
                today = datetime.today()
                age = today.year - dogum_tarihi_obj.year - ((today.month, today.day) < (dogum_tarihi_obj.month, dogum_tarihi_obj.day))
                if age < 18:
                    errors['dogumTarihi'] = '18 yaşından küçükler kayıt olamaz.'
            except ValueError:
                errors['dogumTarihi'] = 'Doğum tarihi formatı hatalı.'

        # Email, TC veya Telefon zaten kayıtlı mı?
        if form.get('email') and form.get('tc') and form.get('telefon'):
            exists = Technician.query.filter(
                or_(Technician.email == form['email'], Technician.tc == form['tc'], Technician.telefon == form['telefon'])
            ).first() or User.query.filter(
                or_(User.email == form['email'], User.tc == form['tc'], User.telefon == form['telefon'])
            ).first()
            if exists:
                errors['genel'] = 'Bu bilgilerle zaten kayıt yapılmış.'

        # Eğer hata varsa formu tekrar göster
        if errors:
            return render_template('register_technician.html', errors=errors, form=form)

        # Kayıt başarılıysa veritabanına ekle
        sifre_hash = generate_password_hash(sifre)
        yeni_technician = Technician(
            ad=form['ad'],
            soyad=form['soyad'],
            email=form['email'],
            telefon=form['telefon'],
            tc=form['tc'],
            dogum_tarihi=dogum_tarihi_obj,
            uzmanlik=form['uzmanlik'],
            destek_modeli=form['destek_modeli'],
            tecrube=form['tecrube'],
            konum=form['konum'],
            referans=form['referans'],
            ek_yetenekler=form['ek_yetenekler'],
            sifre=sifre_hash
        )

        try:
            db.session.add(yeni_technician)
            db.session.commit()
            flash('Tekniker kaydı başarılı!', 'success')
            return redirect(url_for('technician_login'))
        except Exception as e:
            db.session.rollback()
            errors['genel'] = f'Kayıt sırasında hata oluştu: {str(e)}'
            return render_template('register_technician.html', errors=errors, form=form)

    # GET isteğinde boş form göster
    return render_template('register_technician.html', errors={}, form={})


@app.route('/user/dashboard')
@login_required
def user_dashboard():
    # Sadece kullanıcı rolündeki üyeler erişebilir
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    # ------------------ KPI VERİLERİ ------------------
    total_appointments = Appointment.query.filter_by(user_id=current_user.id).count()

    # status alanını case-insensitive kontrol edelim
    completed_appointments = Appointment.query.filter(
    Appointment.user_id == current_user.id,
    func.lower(Appointment.status).in_(['tamamlandı', 'onaylandı'])
).count()

    messages_count = Message.query.filter_by(user_id=current_user.id, is_read=False).count()

    # ------------------ DUYURULAR ------------------
    announcements = Announcement.query.filter_by(target_group='uye') \
                    .order_by(Announcement.date_created.desc()).all()

    # ------------------ SON 5 RANDEVU ------------------
    recent_appointments = Appointment.query.filter_by(user_id=current_user.id) \
                            .order_by(Appointment.date.desc()) \
                            .limit(5).all()

    # ------------------ AYLIK RANDEVU VERİLERİ (BU YIL) ------------------
    month_name = ["", "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran",
                  "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"]
    now = datetime.now()
    monthly_values = []
    monthly_labels = []

    for month in range(1, 13):
        count = Appointment.query.filter(
            Appointment.user_id == current_user.id,
            extract('month', Appointment.date) == month,
            extract('year', Appointment.date) == now.year
        ).count()
        monthly_values.append(count)
        monthly_labels.append(month_name[month])

    # ------------------ TEMPLATE'E GÖNDER ------------------
    return render_template('user_dashboard.html',
                           user=current_user,
                           total_appointments=total_appointments,
                           completed_appointments=completed_appointments,
                           messages_count=messages_count,
                           announcements=announcements,
                           recent_appointments=recent_appointments,
                           monthly_labels=monthly_labels,
                           monthly_values=monthly_values)



@app.route('/randevu/olustur', methods=['GET', 'POST'])
@login_required
def randevu_olustur():
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        date_str = request.form.get('date')
        uzmanlik = request.form.get('uzmanlik')
        destek_modeli = request.form.get('destek_modeli')
        category = request.form.get('category')
        description = request.form.get('description')

        # Validasyonlar
        if not all([date_str, uzmanlik, destek_modeli, category, description]):
            flash('Lütfen tüm alanları doldurun.', 'warning')
            return redirect(url_for('randevu_olustur'))

        try:
            appointment_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if appointment_date < datetime.now().date():
                flash('Geçmiş tarih seçilemez.', 'warning')
                return redirect(url_for('randevu_olustur'))
        except ValueError:
            flash('Geçersiz tarih formatı.', 'warning')
            return redirect(url_for('randevu_olustur'))

        # Direkt randevuyu oluştur, tekniker ataması yapma (tekniker_id None)
        new_appointment = Appointment(
            user_id=current_user.id,
            technician_id=None,
            date=appointment_date,
            uzmanlik=uzmanlik,
            destek_modeli=destek_modeli,
            category=category,
            description=description,
            status='Tekniker Bekliyor'  # Atama yapılmadıysa bu statü
        )

        db.session.add(new_appointment)
        db.session.commit()

        flash('Randevunuz başarıyla oluşturuldu. En Kısa Sürede Onaylancaktır.', 'success')
        return redirect(url_for('user_dashboard'))

    current_date = datetime.now().strftime('%Y-%m-%d')
    return render_template('randevu_olustur.html', current_date=current_date)

@app.route('/user/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # 1) Mevcut şifre kontrolü
        if not check_password_hash(current_user.sifre, current_password):
            flash('Mevcut şifre yanlış.', 'danger')
            return redirect(url_for('change_password'))

        # 2) Yeni şifreler aynı mı?
        if new_password != confirm_password:
            flash('Yeni şifre ile onayı uyuşmuyor.', 'warning')
            return redirect(url_for('change_password'))

        # 3) Yeni şifre minimum uzunluk kontrolü
        if len(new_password) < 6:
            flash('Şifre en az 6 karakter olmalıdır.', 'warning')
            return redirect(url_for('change_password'))

        # 4) Aynı şifre tekrar kullanılmasın
        if check_password_hash(current_user.sifre, new_password):
            flash('Yeni şifre mevcut şifre ile aynı olamaz.', 'warning')
            return redirect(url_for('change_password'))

        # 5) Şifreyi güncelle
        current_user.sifre = generate_password_hash(new_password)
        db.session.commit()

        flash('Şifreniz başarıyla güncellendi.', 'success')
        return redirect(url_for('user_dashboard'))

    # GET isteğinde formu göster
    return render_template('change_password.html')






def get_current_user_real_id():
    """Kullanıcının gerçek ID'sini alır"""
    return int(current_user.get_id().split('-')[1])

# Kullanıcı mesaj listesi sayfası
@app.route('/user/messages', methods=['GET'])
@login_required
def user_messages():
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    user_id = get_current_user_real_id()
    appointments = Appointment.query.filter_by(user_id=user_id, status="Onaylandı").all()
    technicians = [appt.technician for appt in appointments if appt.technician is not None]

    return render_template('user_messages.html', technicians=technicians)

# Belirli tekniker ile mesajları al
@app.route('/user/messages/<int:tech_id>/get_messages', methods=['GET'])
@login_required
def user_get_messages(tech_id):
    user_id = get_current_user_real_id()
    messages = Message.query.filter_by(
        user_id=user_id, technician_id=tech_id
    ).order_by(Message.created_at.asc()).all()

    return jsonify({
        'success': True,
        'messages': [
            {
                'body': m.body,
                'from_user': m.sender_type == 'user',
                'timestamp': m.created_at.strftime("%d.%m.%Y %H:%M")
            } for m in messages
        ]
    })

# Kullanıcı mesaj gönderimi (HTTP)
@app.route('/user/messages/<int:tech_id>/send', methods=['POST'])
@login_required
def user_send_message(tech_id):
    user_id = get_current_user_real_id()
    body = request.form.get('message_body', '').strip()
    if not body:
        return jsonify({'success': False, 'message': 'Mesaj boş olamaz'})

    message = Message(
        user_id=user_id,
        technician_id=tech_id,
        body=body,
        sender_type='user',
        subject='Randevu mesajı',
        created_at=datetime.utcnow()
    )
    db.session.add(message)
    db.session.commit()

    # Socket.IO ile canlı gönderim
    room = f"user_{user_id}_tech_{tech_id}"
    socketio.emit('receive_message', {
        'user_id': user_id,
        'technician_id': tech_id,
        'body': body,
        'sender_type': 'user',
        'timestamp': message.created_at.strftime("%d.%m.%Y %H:%M")
    }, room=room)

    return jsonify({'success': True, 'message': 'Mesaj gönderildi'})

# Socket.IO: Odaya katılma / ayrılma
@socketio.on('join_room')
def handle_join(data):
    user_id = data.get('user_id')
    tech_id = data.get('technician_id')
    if not user_id or not tech_id:
        return
    room = f'user_{user_id}_tech_{tech_id}'
    join_room(room)
    emit('joined_room', {'room': room})

@socketio.on('leave_room')
def handle_leave(data):
    user_id = data.get('user_id')
    tech_id = data.get('technician_id')
    if not user_id or not tech_id:
        return
    room = f'user_{user_id}_tech_{tech_id}'
    leave_room(room)
    emit('left_room', {'room': room})

@socketio.on('send_message')
def handle_send_socket_message(data):
    user_id = int(data.get('user_id'))
    tech_id = int(data.get('technician_id'))
    body = data.get('body', '').strip()
    sender_type = data.get('sender_type', '').lower()

    if not user_id or not tech_id or not body or sender_type not in ['user', 'technician']:
        return

    msg = Message(
        user_id=user_id,
        technician_id=tech_id,
        body=body,
        sender_type=sender_type,
        created_at=datetime.utcnow()
    )
    db.session.add(msg)
    db.session.commit()

    room = f'user_{user_id}_tech_{tech_id}'
    socketio.emit('receive_message', {
        'user_id': user_id,
        'technician_id': tech_id,
        'body': body,
        'sender_type': sender_type,
        'timestamp': msg.created_at.strftime("%d.%m.%Y %H:%M")
    }, room=room)







@app.route('/technician/dashboard')
@login_required
def technician_dashboard():
    # Yetki kontrolü
    if not current_user.get_id().startswith("tech-"):
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    if not technician_id:
        flash("Teknisyen kimliği alınamadı.", "danger")
        return redirect(url_for('index'))

    technician = Technician.query.get(technician_id)
    if not technician:
        flash('Teknisyen bilgisi bulunamadı.', 'danger')
        return redirect(url_for('index'))

    # İstatistikler
    total_appointments = Appointment.query.filter_by(technician_id=technician_id).count()
    pending_appointments = Appointment.query.filter_by(technician_id=technician_id, status='Beklemede').count()
    completed_appointments = Appointment.query.filter_by(technician_id=technician_id, status='Tamamlandı').count()

    # Son 5 randevu (en yeni tarih önce)
    recent_appointments = Appointment.query.filter_by(technician_id=technician_id)\
                                           .order_by(Appointment.date.desc())\
                                           .limit(5).all()

    # Gelen mesajlar sayısı
    total_messages = Message.query.filter_by(technician_id=technician_id).count()

    # Teknisyenlere özel en son 5 duyuru
    announcements = Announcement.query.filter_by(target_group='tekniker')\
                                      .order_by(Announcement.date_created.desc())\
                                      .limit(5).all()

    return render_template('technician_dashboard.html',
                           technician=technician,
                           total_appointments=total_appointments,
                           pending_appointments=pending_appointments,
                           completed_appointments=completed_appointments,
                           recent_appointments=recent_appointments,
                           total_messages=total_messages,
                           announcements=announcements)



@app.route('/technician/appointments')
@login_required
def technician_appointments():
    if not current_user.get_id().startswith("tech-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    technician = Technician.query.get(technician_id)
    if not technician:
        flash('Teknisyen bilgisi bulunamadı.', 'danger')
        return redirect(url_for('index'))

    appointments = Appointment.query.filter_by(technician_id=technician_id).order_by(Appointment.date.desc()).all()

    return render_template('technician_appointments.html', appointments=appointments, technician=technician)


@app.route('/technician/active_appointments')
@login_required 
def technician_active_appointments():
    if not current_user.get_id().startswith("tech-"):
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    
    # Sadece bu teknikerin uzmanlık alanındaki ve kendisine atanmış randevular
    appointments = Appointment.query.filter(
        (Appointment.technician_id == technician_id) |
        (
            (Appointment.technician_id.is_(None)) & 
            (Appointment.uzmanlik.ilike(f"%{current_user.uzmanlik}%"))
        )
    ).filter(
        Appointment.status.in_(['Beklemede', 'Tekniker Bekliyor'])
    ).order_by(Appointment.date.asc()).all()

    return render_template('technician_active_appointments.html', 
                         appointments=appointments,
                         current_user=current_user)



def get_current_user_real_id():
    # Tekniker ID'sini döndür
    return int(current_user.get_id().split('-')[1])

# ------------------------
# Rotalar
# ------------------------
@app.route('/technician/messages')
@login_required
def technician_messages():
    # Sadece teknisyenler erişebilir
    if not current_user.get_id().startswith("tech-"):
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()

    # Onaylı randevulardan kullanıcı ID'lerini al
    approved_appointments = Appointment.query.filter_by(
        technician_id=technician_id,
        status="Onaylandı"
    ).all()
    user_ids = {appt.user_id for appt in approved_appointments}

    users_data = []

    if user_ids:
        # Kullanıcıları çek ve her kullanıcı için son mesaj ve okunmamış sayısını al
        users = User.query.filter(User.id.in_(user_ids)).all()
        for user in users:
            # Son mesaj (kullanıcı veya teknisyen fark etmez)
            last_message = (
                Message.query
                .filter_by(user_id=user.id, technician_id=technician_id)
                .order_by(Message.created_at.desc())
                .first()
            )

            # Okunmamış mesaj sayısı (sadece kullanıcıdan gelen mesajlar)
            unread_count = (
                Message.query
                .filter_by(
                    user_id=user.id,
                    technician_id=technician_id,
                    sender_type='user',
                    is_read=False
                )
                .count()
            )

            users_data.append({
                'user': user,
                'last_message': last_message,
                'unread_count': unread_count
            })

        # Son mesaja göre sırala (WhatsApp tarzı)
        users_data.sort(
            key=lambda x: x['last_message'].created_at if x['last_message'] else datetime.min,
            reverse=True
        )

    return render_template(
        'technician_messages.html',
        users_data=users_data,
        TECHNICIAN_ID=technician_id
    )



@app.route('/technician/messages/<int:user_id>/get_messages')
@login_required
def get_messages(user_id):
    if not current_user.get_id().startswith("tech-"):
        return jsonify(success=False, message="Yetkiniz yok."), 403

    technician_id = get_current_user_real_id()

    messages = Message.query.filter_by(
        technician_id=technician_id,
        user_id=user_id
    ).order_by(Message.created_at.asc()).all()

    messages_data = [
        {
            "id": msg.id,
            "body": msg.body,
            "timestamp": msg.created_at.strftime('%d.%m.%Y %H:%M'),
            "from_technician": msg.sender_type == 'technician',
        }
        for msg in messages
    ]

    # Kullanıcıdan gelen mesajları okunmuş yap
    unread_messages = Message.query.filter_by(
        technician_id=technician_id,
        user_id=user_id,
        sender_type='user',
        is_read=False
    ).all()
    for msg in unread_messages:
        msg.is_read = True
    if unread_messages:
        db.session.commit()

    return jsonify(success=True, messages=messages_data)


@app.route('/technician/send_message', methods=['POST'])
@login_required
def technician_send_message():
    # Sadece teknikerler erişebilir
    if not current_user.get_id().startswith("tech-"):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=False, message="Bu işlem için yetkiniz yok."), 403
        flash("Bu işlem için yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    user_id_raw = request.form.get('user_id')
    message_body = request.form.get('message_body', '').strip()

    # Boş alan kontrolü
    if not user_id_raw or not message_body:
        msg = 'Lütfen tüm alanları doldurun.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=False, message=msg), 400
        flash(msg, 'warning')
        return redirect(url_for('technician_messages'))

    try:
        user_id = int(user_id_raw)  # int dönüşümü güvenli hale getirildi
    except ValueError:
        msg = 'Geçersiz kullanıcı ID.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=False, message=msg), 400
        flash(msg, 'warning')
        return redirect(url_for('technician_messages'))

    try:
        technician_id = get_current_user_real_id()
        subject = f"Tekniker Mesajı - {datetime.now().strftime('%d.%m.%Y %H:%M')}"

        # Mesajı kaydet
        new_message = Message(
            user_id=user_id,
            technician_id=technician_id,
            sender_type='technician',
            subject=subject,
            body=message_body,
            is_read=False,
            created_at=datetime.utcnow()
        )
        db.session.add(new_message)
        db.session.commit()

        # Socket.IO ile mesajı doğru room’a gönder
        room = f"user_{user_id}_tech_{technician_id}"
        socketio.emit('receive_message', {
            'user_id': user_id,
            'technician_id': technician_id,
            'body': message_body,
            'from_technician': True,
            'timestamp': new_message.created_at.strftime('%d.%m.%Y %H:%M')
        }, room=room)

    except Exception as e:
        db.session.rollback()
        print(f"Mesaj gönderme hatası: {e}")
        msg = 'Mesaj gönderilirken hata oluştu.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=False, message=msg), 500
        flash(msg, 'danger')
        return redirect(url_for('technician_messages'))

    # Ajax isteği için JSON dönüşü
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(success=True, message="Mesaj başarıyla gönderildi.")

    flash('Mesaj başarıyla gönderildi.', 'success')
    return redirect(url_for('technician_messages'))



@socketio.on('join_room')
def handle_join(data):
    user_id = data.get('user_id')
    tech_id = data.get('technician_id')
    if not user_id or not tech_id:
        return
    room = f'user_{user_id}_tech_{tech_id}'
    join_room(room)
    emit('joined_room', {'room': room}, room=room)

@socketio.on('leave_room')
def handle_leave(data):
    user_id = data.get('user_id')
    tech_id = data.get('technician_id')
    if not user_id or not tech_id:
        return
    room = f'user_{user_id}_tech_{tech_id}'
    leave_room(room)
    emit('left_room', {'room': room}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    try:
        user_id = int(data.get('user_id'))
        tech_id = int(data.get('technician_id'))
        body = data.get('body', '').strip()
        sender_type = data.get('sender_type', '').lower()
    except (ValueError, AttributeError):
        return

    if not user_id or not tech_id or not body or sender_type not in ['user', 'technician']:
        return

    # Mesajı DB'ye kaydet
    msg = Message(
        user_id=user_id,
        technician_id=tech_id,
        body=body,
        sender_type=sender_type,
        created_at=datetime.utcnow(),
        is_read=False
    )
    db.session.add(msg)
    db.session.commit()

    room = f'user_{user_id}_tech_{tech_id}'
    # Canlı olarak tüm odadaki katılımcılara gönder
    socketio.emit('receive_message', {
        'user_id': user_id,
        'technician_id': tech_id,
        'body': body,
        'from_technician': sender_type == 'technician',
        'timestamp': msg.created_at.strftime('%d.%m.%Y %H:%M')
    }, room=room)




@app.route('/user/appointments')
@login_required
def user_appointments():
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    user_id = get_current_user_real_id()
    appointments = Appointment.query.filter_by(user_id=user_id).order_by(Appointment.date.desc()).all()

    return render_template('user_appointments.html', appointments=appointments)


@app.route('/user/appointment/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user_appointment(id):
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    user_id = get_current_user_real_id()
    appointment = Appointment.query.get_or_404(id)

    # Randevunun kullanıcıya ait olup olmadığını kontrol et
    if appointment.user_id != user_id:
        flash('Bu randevu size ait değil!', 'danger')
        return redirect(url_for('user_appointments'))

    # Onaylanmış randevuyu düzenlemeye çalışıyorsa engelle
    if appointment.status == 'Onaylandı':
        flash('Onaylanmış randevular düzenlenemez!', 'warning')
        return redirect(url_for('user_appointments'))

    if request.method == 'POST':
        try:
            # Tarih ve saat
            appointment.date = datetime.strptime(request.form['date'], '%Y-%m-%dT%H:%M')

            # Diğer alanlar
            appointment.uzmanlik = request.form['uzmanlik']
            appointment.category = request.form['category']
            appointment.description = request.form['description']

            db.session.commit()
            flash('Randevu başarıyla güncellendi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Randevu güncellenirken hata oluştu: {str(e)}', 'danger')

        return redirect(url_for('user_appointments'))

    return render_template('edit_user_appointment.html', appointment=appointment)



@app.route('/technician/appointment_history')
@login_required
def technician_appointment_history():
    if not current_user.get_id().startswith("tech-"):
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for("index"))

    technician_id = get_current_user_real_id()
    page = request.args.get('page', 1, type=int)

    pagination = Appointment.query.filter_by(technician_id=technician_id)\
                                 .order_by(Appointment.date.desc())\
                                 .paginate(page=page, per_page=10, error_out=False)

    return render_template('technician_appointment_history.html',
                           appointments=pagination.items,
                           page=page,
                           total_pages=pagination.pages)


@app.route('/technician/approve/<int:appointment_id>', methods=['POST'])
@login_required
def approve_appointment(appointment_id):
    # 1. Kullanıcının tekniker olduğundan emin ol
    if not current_user.get_id().startswith("tech-"):
        flash("Bu işlem için tekniker yetkisi gerekiyor", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    appointment = Appointment.query.get_or_404(appointment_id)
    
    print(f"Debug - Appointment Technician ID: {appointment.technician_id}, Current Technician ID: {technician_id}")  # Debug için

    # 2. Randevunun bu teknikere ait olduğunu veya atanmamış olduğunu kontrol et
    if appointment.technician_id is not None and appointment.technician_id != technician_id:
        flash("Bu randevuyu onaylama yetkiniz yok", "danger")
        return redirect(url_for('technician_active_appointments'))

    # 3. Eğer randevu atanmamışsa, bu teknikere ata
    if appointment.technician_id is None:
        appointment.technician_id = technician_id
    
    try:
        appointment.status = "Onaylandı"
        db.session.commit()
        flash("Randevu başarıyla onaylandı", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Onaylama sırasında hata oluştu: {str(e)}", "danger")
    
    return redirect(url_for('technician_active_appointments'))


@app.route('/technician/cancel/<int:appointment_id>', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    # 1. Kullanıcının tekniker olduğundan emin ol
    if not current_user.get_id().startswith("tech-"):
        flash("Bu işlem için tekniker yetkisi gerekiyor.", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    appointment = Appointment.query.get_or_404(appointment_id)

    # 2. Randevunun bu teknikere ait olduğunu kontrol et
    if appointment.technician_id is not None and appointment.technician_id != technician_id:
        flash('Bu randevuya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('technician_active_appointments'))

    # 3. Randevu iptal etme işlemi
    try:
        appointment.status = "İptal Edildi"
        db.session.commit()
        flash("Randevu başarıyla iptal edildi.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Hata oluştu: {str(e)}", "danger")

    return redirect(url_for('technician_active_appointments'))


@app.route('/api/user/appointments_status')
@login_required
def api_user_appointments_status():
    # Sadece user tipi kullanıcı erişebilir
    if not current_user.get_id().startswith("user-"):
        return {"error": "Yetkisiz erişim"}, 403

    user_id = get_current_user_real_id()

    appointments = Appointment.query.filter_by(user_id=user_id).order_by(Appointment.date.desc()).all()

    # JSON formatında döndürmek için liste oluştur
    data = []
    for appt in appointments:
        data.append({
            "id": appt.id,
            "date": appt.date.strftime('%d.%m.%Y'),
            "uzmanlik": appt.uzmanlik,
            "category": appt.category,
            "description": appt.description,
            "status": appt.status
        })

    return {"appointments": data}





@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        tc = request.form.get('tc')
        ad = request.form.get('ad')
        soyad = request.form.get('soyad')
        email = request.form.get('email')
        sifre = request.form.get('sifre')
        sifre_onay = request.form.get('sifreOnay')

        if not all([tc, ad, soyad, email, sifre, sifre_onay]):
            flash('Lütfen tüm alanları doldurun.', 'warning')
            return redirect(url_for('register_admin'))

        if sifre != sifre_onay:
            flash('Şifreler uyuşmuyor.', 'danger')
            return redirect(url_for('register_admin'))

        if Admin.query.filter((Admin.tc == tc) | (Admin.email == email)).first():
            flash('Bu TC veya Email zaten kayıtlı.', 'danger')
            return redirect(url_for('register_admin'))

        sifre_hash = generate_password_hash(sifre)

        yeni_admin = Admin(
            tc=tc,
            ad=ad,
            soyad=soyad,
            email=email,
            sifre=sifre_hash
        )

        db.session.add(yeni_admin)
        db.session.commit()

        flash('Admin başarıyla kaydedildi.', 'success')
        return redirect(url_for('index'))

    return render_template('register_admin.html')


# Admin login
@app.route('/login_admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        tc = request.form.get('tc')
        sifre = request.form.get('sifre')

        if not tc or not sifre:
            flash('Lütfen tüm alanları doldurun.', 'warning')
            return redirect(url_for('admin_login'))

        admin = Admin.query.filter_by(tc=tc).first()
        if admin and check_password_hash(admin.sifre, sifre):
            session['admin_id'] = admin.id
            flash('Admin girişi başarılı!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Hatalı TC veya şifre!', 'danger')
            return redirect(url_for('admin_login'))

    return render_template('login_admin.html')


# Admin dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash('Bu sayfaya erişmek için önce admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    admin = Admin.query.get(session['admin_id'])
    users = User.query.all()
    technicians = Technician.query.all()

    return render_template(
        'admin_dashboard.html',
        admin=admin,
        users=users,
        technicians=technicians
    )

# Admin logout
@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_id', None)
    flash('Başarıyla çıkış yapıldı.', 'success')
    return redirect(url_for('index'))


# Tekniker Onayla
@app.route('/admin/tekniker/onayla/<int:id>')
def onayla_tekniker(id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    tekniker = Technician.query.get_or_404(id)
    tekniker.onay = True
    db.session.commit()
    flash(f"{tekniker.ad} {tekniker.soyad} adlı tekniker onaylandı.", 'success')
    return redirect(url_for('admin_dashboard'))


# Tekniker İptal Et
@app.route('/admin/tekniker/iptal/<int:id>')
def iptal_tekniker(id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    tekniker = Technician.query.get_or_404(id)
    tekniker.iptal = True
    tekniker.onay = False
    db.session.commit()
    flash(f"{tekniker.ad} {tekniker.soyad} adlı tekniker iptal edildi ve sisteme giriş yapamaz.", 'success')
    return redirect(url_for('admin_dashboard'))


# Kullanıcı yönetimi
@app.route('/admin/manage_users')
def manage_users():
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    users = User.query.all()
    return render_template("manage_users.html", users=users)


# Tekniker yönetimi
@app.route('/admin/manage_technicians')
def manage_technicians():
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    technicians = Technician.query.all()
    return render_template("manage_technicians.html", technicians=technicians)


@app.route('/admin/manage_appointments')
def manage_appointments():
    # Admin giriş kontrolü
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))
    
    # Randevuları en yeni tarihe göre sırala
    appointments = Appointment.query.order_by(Appointment.date.desc()).all()
    
    return render_template("manage_appointments.html", appointments=appointments)

@app.route('/admin/appointment/cancel/<int:appointment_id>', methods=['POST'])
def admin_cancel_appointment(appointment_id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    appointment = Appointment.query.get_or_404(appointment_id)
    appointment.status = 'iptal'
    db.session.commit()
    flash('Randevu başarıyla iptal edildi.', 'success')
    return redirect(url_for('manage_appointments'))


@app.route('/admin/messages')
def admin_messages():
    if 'admin_id' not in session:
        flash('Bu sayfaya erişmek için önce admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    # Tüm mesajları tarihe göre sırala (yeni önce)
    messages = Message.query.order_by(Message.created_at.desc()).all()
    users = User.query.all()
    technicians = Technician.query.all()

    return render_template(
        'admin_messages.html',
        messages=messages,
        users=users,
        technicians=technicians
    )


@app.route('/admin/messages/delete', methods=['POST'])
def admin_message_delete():
    if 'admin_id' not in session:
        flash('Bu işlem için önce admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    message_id = request.form.get('message_id')
    if not message_id:
        flash('Mesaj ID gönderilmedi.', 'warning')
        return redirect(url_for('admin_messages'))

    try:
        message_id_int = int(message_id)
    except ValueError:
        flash('Geçersiz mesaj ID.', 'warning')
        return redirect(url_for('admin_messages'))

    message = Message.query.get(message_id_int)
    if not message:
        flash('Mesaj bulunamadı.', 'warning')
        return redirect(url_for('admin_messages'))

    try:
        db.session.delete(message)
        db.session.commit()
        flash('Mesaj başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Mesaj silme hatası: {e}")
        flash('Mesaj silinirken bir hata oluştu.', 'danger')

    return redirect(url_for('admin_messages'))




@app.route('/user/edit/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.ad = request.form.get('ad')
        user.soyad = request.form.get('soyad')
        # diğer alanlar güncelle
        db.session.commit()
        flash('Kullanıcı bilgileri güncellendi.', 'success')
        return redirect(url_for('manage_users'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/user/delete/<int:id>', methods=['POST'])
def delete_user(id):
    if 'admin_id' not in session:
        flash('Giriş yapmanız gerekiyor.', 'danger')
        return redirect(url_for('admin_login'))

    user = User.query.get_or_404(id)

    try:
        # Kullanıcıyı sil (appointments ve messages cascade ile otomatik silinecek)
        db.session.delete(user)
        db.session.commit()
        flash(f"{user.ad} {user.soyad} adlı kullanıcı ve ilişkili tüm randevu & mesajları silindi.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Kullanıcı silinirken hata oluştu: {str(e)}", 'danger')

    return redirect(url_for('manage_users'))




@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user_admin(user_id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        try:
            # Temel bilgiler
            user.ad = request.form.get('ad', '').strip()
            user.soyad = request.form.get('soyad', '').strip()
            user.email = request.form.get('email', '').strip()
            user.telefon = request.form.get('telefon', '').strip()
            user.tc = request.form.get('tc', '').strip()
            user.adres = request.form.get('adres', '').strip()
            
            # Dogum tarihi string → date
            dogum_tarihi_str = request.form.get('dogum_tarihi', '').strip()
            if dogum_tarihi_str:
                try:
                    user.dogum_tarihi = datetime.strptime(dogum_tarihi_str, '%Y-%m-%d').date()
                except ValueError:
                    flash('Geçersiz doğum tarihi formatı.', 'warning')
                    return render_template('edit_user.html', user=user)
            else:
                user.dogum_tarihi = None

            # Cinsiyet
            user.cinsiyet = request.form.get('cinsiyet', '').strip()

            # Konum
            konum = request.form.get('konum', '').strip()
            user.konum = konum if konum else None

            db.session.commit()
            flash('Kullanıcı bilgileri başarıyla güncellendi.', 'success')
            return redirect(url_for('manage_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Güncelleme sırasında hata oluştu: {str(e)}', 'danger')
            return render_template('edit_user.html', user=user)

    return render_template('edit_user.html', user=user)

# Duyuru Ekle
@app.route('/admin/duyuru-ekle', methods=['GET', 'POST'])
def announcement_add():
    if 'admin_id' not in session:
        flash('Bu sayfaya erişmek için önce admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    admin = Admin.query.get(session.get('admin_id'))
    if not admin:
        flash('Admin hesabı bulunamadı, lütfen tekrar giriş yapınız.', 'danger')
        session.pop('admin_id', None)
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        baslik = request.form.get('baslik', '').strip()
        icerik = request.form.get('icerik', '').strip()
        hedef_kitle = request.form.get('hedef_kitle')

        if not baslik or not icerik or not hedef_kitle:
            flash('Lütfen tüm alanları eksiksiz doldurun.', 'danger')
            return redirect(url_for('announcement_add'))

        yeni_duyuru = Announcement(
            title=baslik,
            content=icerik,
            target_group=hedef_kitle
        )
        db.session.add(yeni_duyuru)
        db.session.commit()

        flash('Duyuru başarıyla eklendi.', 'success')
        return redirect(url_for('announcement_add'))

    announcements = Announcement.query.order_by(Announcement.date_created.desc()).all()

    return render_template('admin_duyuru_ekle.html', admin=admin, announcements=announcements)



# Duyuru Düzenle
@app.route('/admin/duyuru-duzenle/<int:id>', methods=['GET', 'POST'])
def announcement_edit(id):
    if 'admin_id' not in session:
        flash('Lütfen önce admin girişi yapın.', 'danger')
        return redirect(url_for('admin_login'))

    duyuru = Announcement.query.get_or_404(id)

    if request.method == 'POST':
        duyuru.title = request.form.get('baslik', '').strip()
        duyuru.content = request.form.get('icerik', '').strip()
        duyuru.target_group = request.form.get('hedef_kitle')

        if not duyuru.title or not duyuru.content or not duyuru.target_group:
            flash('Lütfen tüm alanları doldurun.', 'danger')
            return redirect(url_for('announcement_edit', id=id))

        db.session.commit()
        flash('Duyuru başarıyla güncellendi.', 'success')
        return redirect(url_for('announcement_add'))

    return render_template('admin_duyuru_duzenle.html', duyuru=duyuru)


# Duyuru Sil
@app.route('/admin/duyuru-sil/<int:id>', methods=['POST'])
def announcement_delete(id):
    if 'admin_id' not in session:
        flash('Lütfen önce admin girişi yapın.', 'danger')
        return redirect(url_for('admin_login'))

    duyuru = Announcement.query.get_or_404(id)
    db.session.delete(duyuru)
    db.session.commit()

    flash('Duyuru başarıyla silindi.', 'success')
    return redirect(url_for('announcement_add'))





@app.route('/admin/technician/edit/<int:id>', methods=['GET', 'POST'])
def edit_technician(id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    technician = Technician.query.get_or_404(id)

    if request.method == 'POST':
        try:
            # Temel bilgiler
            technician.ad = request.form.get('ad')
            technician.soyad = request.form.get('soyad')
            technician.email = request.form.get('email')
            technician.telefon = request.form.get('telefon')
            technician.tc = request.form.get('tc')

            # Dogum tarihi string → date
            dogum_str = request.form.get('dogum_tarihi')
            if dogum_str:
                technician.dogum_tarihi = datetime.strptime(dogum_str, '%Y-%m-%d').date()

            # Teknik detaylar
            technician.uzmanlik = request.form.get('uzmanlik')
            technician.destek_modeli = request.form.get('destek_modeli')
            technician.tecrube = int(request.form.get('tecrube') or 0)
            technician.konum = request.form.get('konum')
            technician.referans = request.form.get('referans')
            technician.ek_yetenekler = request.form.get('ek_yetenekler')

            # Şifre güncelleme
            sifre = request.form.get('sifre')
            if sifre:
                technician.sifre = generate_password_hash(sifre)

            # Checkboxlar
            technician.onay = 'onay' in request.form
            technician.iptal = 'iptal' in request.form

            db.session.commit()
            flash('Tekniker bilgileri başarıyla güncellendi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Güncelleme sırasında hata oluştu: {str(e)}', 'danger')

        return redirect(url_for('manage_technicians'))

    return render_template('edit_technician.html', technician=technician)


@app.route('/admin/technician/delete/<int:id>', methods=['POST'])
def delete_technician(id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    # Teknikeri getir, yoksa 404 döndür
    technician = Technician.query.get_or_404(id)

    try:
        db.session.delete(technician)
        db.session.commit()
        flash(f'{technician.ad} {technician.soyad} isimli tekniker silindi.', 'success')
    except Exception as e:
        db.session.rollback()  # Hata durumunda işlemi geri al
        flash(f'Tekniker silinirken hata oluştu: {str(e)}', 'danger')

    return redirect(url_for('manage_technicians'))




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)

#import os
#if __name__ == "__main__":
#   port = int(os.environ.get("PORT", 5000))
#    socketio.run(app, host="0.0.0.0", port=port, debug=True)

