import os
import re
import uuid
import random
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from PIL import Image
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect, validate_csrf, ValidationError
from flask_wtf import FlaskForm
import shutil
from sqlalchemy import event
import time
from sqlalchemy import or_, and_

# 允许的图片文件扩展名
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'mov'}

def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in (ALLOWED_EXTENSIONS | ALLOWED_VIDEO_EXTENSIONS)

def is_video_file(filename):
    """检查是否为视频文件"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS

app = Flask(__name__)

# 导入配置
from config import *

# 应用配置
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['THUMBNAIL_FOLDER'] = THUMBNAIL_FOLDER
app.config['THUMBNAIL_SIZE'] = THUMBNAIL_SIZE
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SECURITY_PASSWORD_SALT'] = SECURITY_PASSWORD_SALT
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF token 永不过期

# 邮件配置
app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD

csrf = CSRFProtect(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['THUMBNAIL_FOLDER'], exist_ok=True)
os.makedirs(os.path.join('static', 'uploads', 'avatars'), exist_ok=True)
os.makedirs(os.path.join('static', 'thumbnails', 'avatars'), exist_ok=True)
os.makedirs(os.path.join('static', 'images'), exist_ok=True)

# 定义地区模型
class Region(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('region.id'))
    level = db.Column(db.String(20), nullable=False)  # province, city, district
    children = db.relationship('Region', backref=db.backref('parent', remote_side=[id]))

# 定义圈子模型
class Circle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    region_id = db.Column(db.Integer, db.ForeignKey('region.id'), nullable=False)
    circle_type = db.Column(db.String(20), nullable=False)  # hometown: 老家圈, current: 现居圈
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone(timedelta(hours=8))))
    region = db.relationship('Region', backref='circles')

# 用户和圈子的关联表
user_circles = db.Table('user_circles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')),
    db.Column('circle_id', db.Integer, db.ForeignKey('circle.id', ondelete='CASCADE'))
)

# 帖子和圈子的关联表
post_circles = db.Table('post_circles',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id', ondelete='CASCADE')),
    db.Column('circle_id', db.Integer, db.ForeignKey('circle.id', ondelete='CASCADE'))
)

# 修改User模型，添加地区相关字段
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    phone = db.Column(db.String(20), unique=True)
    nickname = db.Column(db.String(50))  # 昵称
    avatar = db.Column(db.String(200))   # 头像路径
    hometown_province_id = db.Column(db.Integer, db.ForeignKey('region.id'))  # 故乡省
    hometown_city_id = db.Column(db.Integer, db.ForeignKey('region.id'))      # 故乡市
    hometown_district_id = db.Column(db.Integer, db.ForeignKey('region.id'))  # 故乡区
    current_province_id = db.Column(db.Integer, db.ForeignKey('region.id'))   # 现居省
    current_city_id = db.Column(db.Integer, db.ForeignKey('region.id'))       # 现居市
    current_district_id = db.Column(db.Integer, db.ForeignKey('region.id'))   # 现居区
    is_profile_completed = db.Column(db.Boolean, default=False)  # 是否已完善个人信息
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6))
    verification_code_expires = db.Column(db.DateTime)
    posts = db.relationship('Post', backref='author', lazy=True)
    circles = db.relationship('Circle', secondary='user_circles', backref='users')
    
    hometown_province = db.relationship('Region', foreign_keys=[hometown_province_id])
    hometown_city = db.relationship('Region', foreign_keys=[hometown_city_id])
    hometown_district = db.relationship('Region', foreign_keys=[hometown_district_id])
    current_province = db.relationship('Region', foreign_keys=[current_province_id])
    current_city = db.relationship('Region', foreign_keys=[current_city_id])
    current_district = db.relationship('Region', foreign_keys=[current_district_id])

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_display_name(self):
        base_name = self.nickname or self.email or self.phone
        return base_name

# 定义Like模型
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone(timedelta(hours=8))))
    user = db.relationship('User', backref='likes')

# 定义Notification模型
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 接收通知的用户
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 发送通知的用户
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)  # 相关的帖子
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)  # 相关的评论
    type = db.Column(db.String(20))  # 通知类型：like, comment, reply
    content = db.Column(db.Text)  # 通知内容
    is_read = db.Column(db.Boolean, default=False)  # 是否已读
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone(timedelta(hours=8))))
    
    user = db.relationship('User', foreign_keys=[user_id], backref='notifications_received')
    sender = db.relationship('User', foreign_keys=[sender_id], backref='notifications_sent')
    post = db.relationship('Post', backref='notifications')
    comment = db.relationship('Comment', backref='notifications')
    
    @property
    def url(self):
        if self.type == 'like':
            return url_for('index', _anchor=f'post-{self.post_id}')
        elif self.type in ['comment', 'reply']:
            return url_for('index', show_comments=self.post_id, _anchor=f'comment-{self.comment_id}')
        return url_for('index')

# 定义Comment模型
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    images = db.Column(db.JSON, default=list)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone(timedelta(hours=8))))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id', name='fk_comment_parent', use_alter=True), nullable=True)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_reply_to_user'), nullable=True)
    author = db.relationship('User', backref='comments', foreign_keys=[user_id])
    reply_to = db.relationship('User', foreign_keys=[reply_to_id])
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), post_update=True,
                           cascade='all, delete-orphan')

# 定义Topic模型
class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    post_count = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone(timedelta(hours=8))))

# 帖子和话题的关联表
post_topics = db.Table('post_topics',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id', ondelete='CASCADE')),
    db.Column('topic_id', db.Integer, db.ForeignKey('topic.id', ondelete='CASCADE'))
)

# 修改Post模型，添加圈子关联
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    images = db.Column(db.JSON, default=list)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone(timedelta(hours=8))))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topics = db.relationship('Topic', secondary='post_topics', backref='posts')
    circles = db.relationship('Circle', secondary='post_circles', backref='posts')
    likes = db.relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    visibility = db.Column(db.String(20))  # 帖子可见性

# 创建数据库表
with app.app_context():
    db.drop_all()  # 先删除所有表
    db.create_all()  # 重新创建所有表

def create_thumbnail(image_path, thumbnail_path, size):
    """创建等比例缩略图，保持图片比例"""
    with Image.open(image_path) as img:
        # 计算缩放比例
        width, height = img.size
        ratio = min(size[0]/width, size[1]/height)
        new_size = (int(width * ratio), int(height * ratio))
        
        # 缩放图片
        img = img.resize(new_size, Image.Resampling.LANCZOS)
        
        # 创建新的白色背景图片
        thumb = Image.new('RGB', size, (255, 255, 255))
        
        # 将缩放后的图片粘贴到中心位置
        x = (size[0] - new_size[0]) // 2
        y = (size[1] - new_size[1]) // 2
        thumb.paste(img, (x, y))
        
        # 保存缩略图
        thumb.save(thumbnail_path, quality=95, optimize=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_verification_email(user):
    # 生成验证码
    verification_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    user.verification_code = verification_code
    user.verification_code_expires = datetime.now() + timedelta(minutes=10)
    db.session.commit()

    # 发送验证邮件
    msg = Message('验证您的邮箱',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'您的验证码是：{verification_code}，10分钟内有效。'
    mail.send(msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        # 验证输入
        if not email:
            flash('必须提供邮箱地址', 'error')
            return redirect(url_for('register'))

        if not password or len(password) < 6:
            flash('密码长度至少为6位', 'error')
            return redirect(url_for('register'))

        # 检查邮箱/手机号是否已存在
        if email and User.query.filter_by(email=email).first():
            flash('该邮箱已被注册', 'error')
            return redirect(url_for('register'))

        if phone and User.query.filter_by(phone=phone).first():
            flash('该手机号已被注册', 'error')
            return redirect(url_for('register'))

        # 创建新用户
        # 如果手机号为空字符串，将其设置为None
        phone = phone if phone else None
        user = User(email=email, phone=phone)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        send_verification_email(user)
        flash('验证码已发送到您的邮箱', 'info')
        return redirect(url_for('verify_email'))

    return render_template('register.html')

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        code = request.form.get('code')
        user = User.query.filter_by(verification_code=code).first()

        if not user or user.verification_code_expires < datetime.now():
            flash('验证码无效或已过期', 'error')
            return redirect(url_for('verify_email'))

        user.is_verified = True
        user.verification_code = None
        user.verification_code_expires = None
        db.session.commit()

        login_user(user)
        flash('邮箱验证成功！', 'success')
        return redirect(url_for('index'))

    return render_template('verify_email.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')  # 邮箱或手机号
        password = request.form.get('password')
        remember = request.form.get('remember', False)  # 获取记住我选项

        # 查找用户
        user = User.query.filter((User.email == identifier) | 
                                (User.phone == identifier)).first()

        if user and user.check_password(password):
            # 使用remember参数登录用户，设置session过期时间为30天
            login_user(user, remember=remember, duration=timedelta(days=30))
            return redirect(url_for('index'))

        flash('用户名或密码错误', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if like:
        db.session.delete(like)
        liked = False
    else:
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        liked = True
        # 创建点赞通知
        create_notification(
            user_id=post.author_id,
            sender_id=current_user.id,
            type='like',
            content=f'{current_user.get_display_name()} 赞了你的微博',
            post_id=post_id
        )
    
    db.session.commit()
    
    # 获取所有点赞用户的名字
    likes_users = []
    for like in post.likes:
        user = User.query.get(like.user_id)
        if user:
            likes_users.append(user.get_display_name())
    likes_users_str = '、'.join(likes_users)
    
    return jsonify({
        'success': True, 
        'liked': liked, 
        'likes_count': post.likes.count(),
        'likes_users': likes_users_str
    })

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('content', '')
    image = request.files.get('image')
    parent_id = request.args.get('parent_id', type=int)
    reply_to_id = request.args.get('reply_to_id', type=int)
    
    if not content and not image:
        return jsonify({'success': False, 'message': '评论内容不能为空'}), 400
    
    try:
        comment = Comment(
            content=content, 
            author=current_user, 
            post=post,
            parent_id=parent_id,
            reply_to_id=reply_to_id
        )
        
        comment.images = []
        
        if image and image.filename:
            ext = os.path.splitext(image.filename)[1]
            unique_filename = f"{uuid.uuid4()}{ext}"
            
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            image.save(image_path)
            
            thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], unique_filename)
            create_thumbnail(image_path, thumbnail_path, app.config['THUMBNAIL_SIZE'])
            
            comment.images.append({
                'filename': unique_filename,
                'original': f"uploads/{unique_filename}",
                'thumbnail': f"thumbnails/{unique_filename}"
            })
        
        db.session.add(comment)
        db.session.commit()
        
        # 创建评论通知
        if parent_id:
            # 如果是回复评论
            parent_comment = Comment.query.get(parent_id)
            create_notification(
                user_id=parent_comment.user_id,
                sender_id=current_user.id,
                type='reply',
                content=f'{current_user.get_display_name()} 回复了你的评论',
                post_id=post_id,
                comment_id=comment.id
            )
        else:
            # 如果是评论微博
            create_notification(
                user_id=post.author_id,
                sender_id=current_user.id,
                type='comment',
                content=f'{current_user.get_display_name()} 评论了你的微博',
                post_id=post_id,
                comment_id=comment.id
            )
        
        # 确保评论区保持展开状态
        return jsonify({
            'success': True,
            'message': '评论成功',
            'show_comments': True
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': '评论失败：' + str(e)
        }), 500

@app.route('/')
def index():
    # 获取查询参数
    page = request.args.get('page', 1, type=int)
    topic = request.args.get('topic')
    circle_id = request.args.get('circle')
    
    # 构建基础查询
    query = Post.query
    
    # 如果用户已登录，获取其可见的帖子
    if current_user.is_authenticated:
        # 获取用户所在的圈子ID列表
        user_circle_ids = [circle.id for circle in current_user.circles]
        
        # 构建可见性条件：公开帖子 OR 用户所在圈子的帖子
        visibility_condition = or_(
            Post.visibility == 'public',
            and_(
                Post.visibility.like('circle_%'),
                Post.visibility.in_(['circle_' + str(id) for id in user_circle_ids])
            )
        )
        query = query.filter(visibility_condition)
    else:
        # 未登录用户只能看到公开帖子
        query = query.filter_by(visibility='public')
    
    # 按话题筛选
    if topic:
        query = query.join(Post.topics).filter(Topic.name == topic)
    
    # 按圈子筛选
    if circle_id:
        query = query.filter(Post.visibility == f'circle_{circle_id}')
    
    # 按时间倒序排序并分页
    posts = query.order_by(Post.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False)
    
    return render_template('index.html', posts=posts, current_topic=topic)

@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content')
    visibility = request.form.get('visibility')
    image = request.files.get('image')
    
    if not content:
        flash('内容不能为空', 'danger')
        return redirect(url_for('index'))
    
    # 如果选择了圈子可见性，检查用户是否属于该圈子
    if visibility.startswith('circle_'):
        circle_id = int(visibility.split('_')[1])
        if not any(circle.id == circle_id for circle in current_user.circles):
            flash('您不属于选择的圈子', 'danger')
            return redirect(url_for('index'))
    
    # 创建帖子
    post = Post(
        content=content,
        author=current_user,
        visibility=visibility
    )
    
    # 处理图片上传
    if image and allowed_file(image.filename):
        filename = secure_filename(f"post_{int(time.time())}_{image.filename}")
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'posts', filename)
        os.makedirs(os.path.dirname(image_path), exist_ok=True)
        image.save(image_path)
        post.image = os.path.join('posts', filename)
    
    # 提取并处理话题标签
    topics = extract_topics(content)
    for topic_name in topics:
        topic = Topic.query.filter_by(name=topic_name).first()
        if not topic:
            topic = Topic(name=topic_name)
            db.session.add(topic)
        post.topics.append(topic)
    
    db.session.add(post)
    db.session.commit()
    
    flash('发布成功', 'success')
    return redirect(url_for('index'))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # 检查是否是帖子作者
    if post.author_id != current_user.id:
        return jsonify({'success': False, 'message': '没有权限删除此帖子'})
    
    try:
        # 删除相关的图片文件
        if post.images:
            for image in post.images:
                # 删除原图
                original_path = os.path.join(app.root_path, 'static', image['original'])
                if os.path.exists(original_path):
                    os.remove(original_path)
                
                # 删除缩略图
                thumbnail_path = os.path.join(app.root_path, 'static', image['thumbnail'])
                if os.path.exists(thumbnail_path):
                    os.remove(thumbnail_path)
        
        # 更新话题计数
        for topic in post.topics:
            if topic.post_count > 0:
                topic.post_count -= 1
        
        # 删除帖子（级联删除相关的点赞和评论）
        db.session.delete(post)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        error_msg = f'删除失败: {str(e)}'
        print(error_msg)
        return jsonify({'success': False, 'message': error_msg})

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # 验证当前用户是否为评论作者
    if comment.user_id != current_user.id:
        return jsonify({'success': False, 'message': '无权删除此评论'}), 403
    
    try:
        # 删除评论相关的图片文件
        if comment.images:
            for image in comment.images:
                # 删除原图
                original_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(image['original']))
                if os.path.exists(original_path):
                    os.remove(original_path)
                
                # 删除缩略图
                thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], os.path.basename(image['thumbnail']))
                if os.path.exists(thumbnail_path):
                    os.remove(thumbnail_path)
        
        # 删除数据库中的评论记录
        db.session.delete(comment)
        db.session.commit()
        
        # 更新评论数量
        post = Post.query.get(comment.post_id)
        comments_count = post.comments.count()
        
        return jsonify({
            'success': True,
            'comments_count': comments_count
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': '删除评论失败：' + str(e)
        }), 500

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # 获取表单数据
        nickname = request.form.get('nickname')
        hometown_province_id = request.form.get('hometown_province')
        hometown_city_id = request.form.get('hometown_city')
        hometown_district_id = request.form.get('hometown_district')
        current_province_id = request.form.get('current_province')
        current_city_id = request.form.get('current_city')
        current_district_id = request.form.get('current_district')
        
        # 处理头像上传
        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar and allowed_file(avatar.filename):
                filename = secure_filename(f"avatar_{current_user.id}_{int(time.time())}{os.path.splitext(avatar.filename)[1]}")
                avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars', filename)
                os.makedirs(os.path.dirname(avatar_path), exist_ok=True)
                avatar.save(avatar_path)
                current_user.avatar = os.path.join('avatars', filename)

        # 更新用户信息
        current_user.nickname = nickname
        current_user.hometown_province_id = hometown_province_id
        current_user.hometown_city_id = hometown_city_id
        current_user.hometown_district_id = hometown_district_id
        current_user.current_province_id = current_province_id
        current_user.current_city_id = current_city_id
        current_user.current_district_id = current_district_id
        
        # 检查是否所有必填字段都已填写
        if (current_user.avatar and current_user.nickname and
            all([hometown_province_id, hometown_city_id, hometown_district_id,
                 current_province_id, current_city_id, current_district_id])):
            current_user.is_profile_completed = True
            
            # 更新用户圈子
            update_user_circles(current_user)
        
        db.session.commit()
        flash('个人资料已更新', 'success')
        return redirect(url_for('profile'))
    
    # GET请求：获取所有省份数据
    provinces = Region.query.filter_by(level='province').all()
    return render_template('profile.html', provinces=provinces)

def update_user_circles(user):
    """更新用户的圈子成员关系"""
    # 清除用户现有的圈子关系
    user.circles = []
    
    # 添加故乡圈子
    hometown_province = Region.query.get(user.hometown_province_id)
    hometown_city = Region.query.get(user.hometown_city_id)
    hometown_district = Region.query.get(user.hometown_district_id)
    
    # 添加现居地圈子
    current_province = Region.query.get(user.current_province_id)
    current_city = Region.query.get(user.current_city_id)
    current_district = Region.query.get(user.current_district_id)
    
    # 获取或创建相应的圈子
    circles_to_add = []
    
    # 故乡圈子
    hometown_district_circle = Circle.query.filter_by(
        region_id=hometown_district.id,
        circle_type='hometown'
    ).first() or Circle(
        name=f"{hometown_district.name}老乡圈",
        region_id=hometown_district.id,
        circle_type='hometown'
    )
    circles_to_add.append(hometown_district_circle)
    
    # 现居地城市圈子
    current_city_circle = Circle.query.filter_by(
        region_id=current_city.id,
        circle_type='current'
    ).first() or Circle(
        name=f"{current_city.name}同城圈",
        region_id=current_city.id,
        circle_type='current'
    )
    circles_to_add.append(current_city_circle)
    
    # 现居地区县圈子
    current_district_circle = Circle.query.filter_by(
        region_id=current_district.id,
        circle_type='current'
    ).first() or Circle(
        name=f"{current_district.name}同城圈",
        region_id=current_district.id,
        circle_type='current'
    )
    circles_to_add.append(current_district_circle)
    
    # 将用户添加到这些圈子中
    for circle in circles_to_add:
        if circle not in user.circles:
            user.circles.append(circle)
            db.session.add(circle)

REPLIES_PER_PAGE = 3  # 每页显示的子评论数量

@app.route('/get_comments/<int:post_id>')
@login_required
def get_comments(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('_comments.html', post=post)

@app.route('/get_more_replies/<int:comment_id>/<int:page>')
@login_required
def get_more_replies(comment_id, page):
    comment = Comment.query.get_or_404(comment_id)
    # 获取分页的回复，使用 offset 和 limit 进行分页
    replies = Comment.query.filter_by(parent_id=comment_id)\
        .order_by(Comment.created_at.asc())\
        .offset((page - 1) * REPLIES_PER_PAGE)\
        .limit(REPLIES_PER_PAGE).all()
    
    # 获取总回复数
    total_replies = Comment.query.filter_by(parent_id=comment_id).count()
    has_more = total_replies > page * REPLIES_PER_PAGE
    
    # 使用 render_template_string 而不是 render_template
    return render_template('_replies.html', 
                         replies=replies, 
                         comment=comment,
                         current_page=page,
                         has_more=has_more)

@app.route('/user/<int:user_id>')
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    # 获取用户的所有微博，按时间倒序排列
    posts = db.session.query(Post, User)\
        .join(User, Post.author_id == User.id)\
        .filter(Post.author_id == user_id)\
        .order_by(Post.created_at.desc()).all()
    return render_template('user_profile.html', profile_user=user, posts=posts)

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        # 获取未读通知数量
        unread_notifications_count = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()
        
        # 获取最近的通知
        recent_notifications = Notification.query.filter_by(
            user_id=current_user.id
        ).order_by(Notification.created_at.desc()).limit(5).all()
        
        # 获取总通知数量
        notifications_count = Notification.query.filter_by(
            user_id=current_user.id
        ).count()
        
        return {
            'unread_notifications_count': unread_notifications_count,
            'recent_notifications': recent_notifications,
            'notifications_count': notifications_count
        }
    return {}

@app.route('/notifications')
@login_required
def notifications():
    # 获取所有通知
    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).all()
    
    # 将所有未读通知标记为已读
    for notification in notifications:
        if not notification.is_read:
            notification.is_read = True
    db.session.commit()
    
    return render_template('notifications.html', notifications=notifications)

def create_notification(user_id, sender_id, type, content, post_id=None, comment_id=None):
    """创建新的通知"""
    if user_id != sender_id:  # 不给自己发送通知
        notification = Notification(
            user_id=user_id,
            sender_id=sender_id,
            type=type,
            content=content,
            post_id=post_id,
            comment_id=comment_id
        )
        db.session.add(notification)
        db.session.commit()

@app.template_filter('timesince')
def timesince_filter(dt):
    """计算时间差的过滤器"""
    now = datetime.now(timezone(timedelta(hours=8)))
    diff = now - dt
    
    if diff.days > 365:
        return f"{diff.days // 365}年前"
    elif diff.days > 30:
        return f"{diff.days // 30}个月前"
    elif diff.days > 0:
        return f"{diff.days}天前"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600}小时前"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60}分钟前"
    else:
        return "刚刚"

# 定期清理未使用的图片文件
@app.cli.command('cleanup-images')
def cleanup_images():
    """清理未被任何帖子引用的图片文件"""
    # 获取所有帖子引用的图片路径
    used_images = set()
    posts = Post.query.all()
    for post in posts:
        if post.images:
            for image in post.images:
                used_images.add(os.path.join(app.root_path, 'static', image['original']))
                used_images.add(os.path.join(app.root_path, 'static', image['thumbnail']))
    
    # 检查并删除未使用的图片
    uploads_dir = os.path.join(app.root_path, 'static', 'uploads')
    thumbnails_dir = os.path.join(app.root_path, 'static', 'thumbnails')
    
    for directory in [uploads_dir, thumbnails_dir]:
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path not in used_images:
                    try:
                        os.remove(file_path)
                        print(f'Removed unused file: {file_path}')
                    except Exception as e:
                        print(f'Error removing {file_path}: {e}')

# 监听删除帖子事件，更新话题计数
@event.listens_for(Post, 'after_delete')
def update_topic_count_on_post_delete(mapper, connection, target):
    for topic in target.topics:
        if topic.post_count > 0:
            topic.post_count -= 1

# 地区数据API路由
@app.route('/api/regions/cities/<int:province_id>')
@login_required
def get_cities(province_id):
    cities = Region.query.filter_by(parent_id=province_id, level='city').all()
    return jsonify([{'id': city.id, 'name': city.name} for city in cities])

@app.route('/api/regions/districts/<int:city_id>')
@login_required
def get_districts(city_id):
    districts = Region.query.filter_by(parent_id=city_id, level='district').all()
    return jsonify([{'id': district.id, 'name': district.name} for district in districts])

@app.route('/circle/<int:circle_id>')
@login_required
def circle_detail(circle_id):
    circle = Circle.query.get_or_404(circle_id)
    
    # 检查用户是否有权限访问该圈子
    if circle not in current_user.circles:
        flash('您不是该圈子的成员', 'danger')
        return redirect(url_for('index'))
    
    # 获取分页参数
    page = request.args.get('page', 1, type=int)
    
    # 获取圈子内的帖子
    posts = Post.query.filter_by(visibility=f'circle_{circle_id}')\
        .order_by(Post.created_at.desc())\
        .paginate(page=page, per_page=10, error_out=False)
    
    return render_template('circle.html', circle=circle, posts=posts)

@app.route('/my_circles')
@login_required
def my_circles():
    # 获取用户所在的所有圈子
    hometown_circles = [c for c in current_user.circles if c.circle_type == 'hometown']
    current_circles = [c for c in current_user.circles if c.circle_type == 'current']
    
    return render_template('my_circles.html', 
                         hometown_circles=hometown_circles,
                         current_circles=current_circles)

# 添加匿名用户类
class AnonymousUser(AnonymousUserMixin):
    def get_display_name(self):
        return '游客'

# 设置匿名用户类
login_manager.anonymous_user = AnonymousUser

if __name__ == '__main__':
    app.run(debug=True)