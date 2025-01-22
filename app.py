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
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect, validate_csrf, ValidationError
from flask_wtf import FlaskForm
import shutil
from sqlalchemy import event

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

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    phone = db.Column(db.String(20), unique=True)
    nickname = db.Column(db.String(50))  # 昵称
    avatar = db.Column(db.String(200))   # 头像路径
    location = db.Column(db.String(50))  # 工作地
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6))
    verification_code_expires = db.Column(db.DateTime)
    posts = db.relationship('Post', backref='author', lazy=True)

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

# 定义Post模型
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    images = db.Column(db.JSON, default=list)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone(timedelta(hours=8))))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topics = db.relationship('Topic', secondary='post_topics', backref='posts')
    likes = db.relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')

# 创建数据库表
with app.app_context():
    db.create_all()

def create_thumbnail(image_path, thumbnail_path, size):
    """创建等比例缩略图，保持图片比例和正确的方向"""
    with Image.open(image_path) as img:
        # 获取 EXIF 数据
        try:
            exif = img._getexif()
            if exif is not None:
                # EXIF 方向标签
                orientation_key = 274  # 0x0112
                if orientation_key in exif:
                    orientation = exif[orientation_key]
                    # 根据方向信息旋转图片
                    if orientation == 3:
                        img = img.rotate(180, expand=True)
                    elif orientation == 6:
                        img = img.rotate(270, expand=True)
                    elif orientation == 8:
                        img = img.rotate(90, expand=True)
        except (AttributeError, KeyError, IndexError):
            # 处理没有 EXIF 或读取失败的情况
            pass

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
        
        # 保存缩略图，保持原图的 EXIF 数据
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

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    from flask_wtf import FlaskForm
    form = FlaskForm()
    
    # 获取话题筛选参数
    topic_name = request.args.get('topic')
    
    if request.method == 'POST':
        if not form.validate():
            flash('表单验证失败，请重试', 'danger')
            return redirect(url_for('index'))
        
        content = request.form.get('content', '')
        images = request.files.getlist('image')
        
        if not content and not images:
            flash('内容和图片至少需要一个', 'danger')
            return redirect(url_for('index'))
        
        try:
            post = Post(content=content, author=current_user)
            
            # 解析话题标签 - 修改正则表达式以准确匹配#后到空格前的内容
            topics = re.findall(r'#([^\s#]+)', content)
            for topic_name in topics:
                # 移除可能存在的标点符号
                topic_name = topic_name.strip(',.!?，。！？')
                topic = Topic.query.filter_by(name=topic_name).first()
                if not topic:
                    topic = Topic(name=topic_name, post_count=0)
                    db.session.add(topic)
                if topic.post_count is None:
                    topic.post_count = 0
                topic.post_count += 1
                post.topics.append(topic)
            
            # 处理图片上传
            if images:
                image_list = []
                for image in images:
                    if image and allowed_file(image.filename):
                        filename = secure_filename(image.filename)
                        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                        unique_filename = f"{timestamp}_{filename}"
                        
                        # 保存原图
                        original_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                        image.save(original_path)
                        
                        # 创建缩略图
                        thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], unique_filename)
                        create_thumbnail(original_path, thumbnail_path, app.config['THUMBNAIL_SIZE'])
                        
                        # 记录图片信息
                        image_list.append({
                            'original': os.path.join('uploads', unique_filename),
                            'thumbnail': os.path.join('thumbnails', unique_filename)
                        })
                
                post.images = image_list
            
            db.session.add(post)
            db.session.commit()
            
            flash('发布成功', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'发布失败：{str(e)}', 'danger')
            return redirect(url_for('index'))
    
    # 获取热门话题
    hot_topics = Topic.query.filter(Topic.post_count > 0).order_by(Topic.post_count.desc()).limit(10).all()
    
    # 构建基础查询
    query = db.session.query(Post, User).join(User, Post.author_id == User.id)
    
    # 如果指定了话题，添加话题筛选条件
    if topic_name:
        query = query.join(post_topics).join(Topic).filter(Topic.name == topic_name)
    
    # 获取所有帖子，按时间倒序排列
    posts = query.order_by(Post.created_at.desc()).all()
    
    # 处理图片 URL
    for post, user in posts:
        if post.images:
            for image in post.images:
                image['thumbnail_url'] = url_for('static', filename=image['thumbnail'])
                image['original_url'] = url_for('static', filename=image['original'])
    
    return render_template('index.html', 
                         posts=posts, 
                         form=form, 
                         hot_topics=hot_topics,
                         current_topic=topic_name)  # 传递当前选中的话题到模板

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
        nickname = request.form.get('nickname')
        location = request.form.get('location')
        avatar = request.files.get('avatar')
        
        if nickname:
            current_user.nickname = nickname
            
        if location:
            current_user.location = location
        else:
            current_user.location = None  # 如果用户清空了工作地，则设为 None
        
        if avatar and avatar.filename:
            # 生成唯一的文件名
            ext = os.path.splitext(avatar.filename)[1]
            unique_filename = f"avatar_{current_user.id}_{uuid.uuid4()}{ext}"
            
            # 确保头像目录存在
            avatar_folder = os.path.join('static', 'uploads', 'avatars')
            os.makedirs(avatar_folder, exist_ok=True)
            
            # 保存头像
            avatar_path = os.path.join(avatar_folder, unique_filename)
            avatar.save(avatar_path)
            
            # 生成并保存头像缩略图
            thumbnail_folder = os.path.join('static', 'thumbnails', 'avatars')
            os.makedirs(thumbnail_folder, exist_ok=True)
            thumbnail_path = os.path.join(thumbnail_folder, unique_filename)
            
            # 创建正方形缩略图
            with Image.open(avatar_path) as img:
                # 确定裁剪尺寸
                width, height = img.size
                size = min(width, height)
                left = (width - size) // 2
                top = (height - size) // 2
                right = left + size
                bottom = top + size
                
                # 裁剪为正方形并调整大小
                img = img.crop((left, top, right, bottom))
                img.thumbnail((100, 100))  # 调整为100x100的缩略图
                img.save(thumbnail_path)
            
            # 更新用户头像路径
            current_user.avatar = f"uploads/avatars/{unique_filename}"
        
        db.session.commit()
        flash('个人资料已更新', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

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

if __name__ == '__main__':
    app.run(debug=True)