from flask import Flask, request, render_template, redirect, url_for
import os
import pandas as pd
import plotly.graph_objs as go
from plotly.offline import plot
from flask import send_file
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import flash
from datetime import datetime

app = Flask(__name__)
@app.context_processor
def inject_now():
    from datetime import datetime
    return {'current_year': datetime.now().year}

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-local')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class UploadHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    upload_time = db.Column(db.DateTime, default=pd.Timestamp.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Configuration
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Routes
@app.route('/')
@login_required
def home():
    return redirect(url_for('upload_page'))

@app.route('/upload')
@login_required
def upload_page():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part"
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file"

    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        # Save upload record
        new_upload = UploadHistory(
            filename=file.filename,
            user_id=current_user.id
        )
        db.session.add(new_upload)
        db.session.commit()

        return redirect(url_for('upload_success', filename=file.filename))
    
@app.route('/report/<filename>')
@login_required
def upload_success(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(filepath)

    # Add 'Total' column
    df['Total'] = df['Quantity'] * df['Price']

    # Summary metrics
    total_revenue = df['Total'].sum()
    unique_customers = df['Customer'].nunique()

    # Sales trend chart (line)
    sales_by_date = df.groupby('Date')['Total'].sum().reset_index()
    fig1 = go.Figure()
    fig1.add_trace(go.Scatter(
        x=sales_by_date['Date'],
        y=sales_by_date['Total'],
        mode='lines+markers',
        name='Sales Trend'
    ))
    fig1.update_layout(
        title='Sales Trend Over Time',
        xaxis_title='Date',
        yaxis_title='Total Sales ($)',
        margin=dict(l=20, r=20, t=40, b=20)
    )
    chart1_html = plot(fig1, output_type='div', include_plotlyjs=True)

    # Top 5 products chart (bar)
    sales_by_product = df.groupby('Product')['Total'].sum().sort_values(ascending=False).head(5).reset_index()
    fig2 = go.Figure()
    fig2.add_trace(go.Bar(
        x=sales_by_product['Total'],
        y=sales_by_product['Product'],
        orientation='h',
        name='Top Products'
    ))
    fig2.update_layout(
        title='Top 5 Products by Sales',
        xaxis_title='Total Sales ($)',
        yaxis_title='Product',
        margin=dict(l=20, r=20, t=40, b=20)
    )
    chart2_html = plot(fig2, output_type='div', include_plotlyjs=False)
    
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Render report page
    return render_template(
        'report.html',
        filename=filename,
        total_revenue=total_revenue,
        unique_customers=unique_customers,
        sales_by_date=sales_by_date.to_dict(orient='records'),
        chart1_html=chart1_html,
        chart2_html=chart2_html,
        generated_at=generated_at
    )

@app.route('/download/<filename>')
def download_excel(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(filepath)
    df['Total'] = df['Quantity'] * df['Price']

    total_revenue = df['Total'].sum()
    unique_customers = df['Customer'].nunique()
    sales_by_date = df.groupby('Date')['Total'].sum().reset_index()
    top_products = df.groupby('Product')['Total'].sum().sort_values(ascending=False).head(5).reset_index()

    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        summary_df = pd.DataFrame({
            'Metric': ['Total Revenue', 'Unique Customers'],
            'Value': [total_revenue, unique_customers]
        })
        summary_df.to_excel(writer, index=False, sheet_name='Summary')

        sales_by_date.to_excel(writer, index=False, sheet_name='Sales by Date')
        top_products.to_excel(writer, index=False, sheet_name='Top 5 Products')
        df.to_excel(writer, index=False, sheet_name='Raw Data')

    output.seek(0)
    return send_file(
        output,
        download_name=f'report_{filename}.xlsx',
        as_attachment=True,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect('/register')

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/')
        else:
            flash('Login failed. Check your username or password.')
            return redirect('/login')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/my-uploads')
@login_required
def my_uploads():
    uploads = UploadHistory.query.filter_by(user_id=current_user.id).order_by(UploadHistory.upload_time.desc()).all()
    return render_template('my_uploads.html', uploads=uploads)

@app.route('/delete/<int:upload_id>', methods=['POST'])
@login_required
def delete_upload(upload_id):
    upload = UploadHistory.query.get_or_404(upload_id)

    # Check ownership
    if upload.user_id != current_user.id:
        return "Unauthorized", 403

    # File path
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    file_path = os.path.join(user_folder, upload.filename)

    # Delete file from disk
    if os.path.exists(file_path):
        os.remove(file_path)

    # Optionally remove folder if empty
    if os.path.exists(user_folder) and not os.listdir(user_folder):
        os.rmdir(user_folder)


    # Delete record from DB
    db.session.delete(upload)
    db.session.commit()

    return redirect(url_for('my_uploads'))

if __name__ == '__main__':
    app.run(debug=True)
