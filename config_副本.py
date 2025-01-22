import os

# Flask应用配置
SECRET_KEY = 'your-secret-key'
SECURITY_PASSWORD_SALT = 'your-security-password-salt'

# 数据库配置
SQLALCHEMY_DATABASE_URI = 'sqlite:////Users/wangqi/trae/instance/posts.db'

# 文件上传配置
UPLOAD_FOLDER = os.path.join('static', 'uploads')
THUMBNAIL_FOLDER = os.path.join('static', 'thumbnails')
THUMBNAIL_SIZE = (150, 150)

# 邮件服务器配置
MAIL_SERVER = 'smtp.163.com'
MAIL_PORT = 25
MAIL_USE_TLS = True
MAIL_USE_SSL = False
MAIL_USERNAME = 'hislota@163.com'
MAIL_PASSWORD = 'BXUycYcDWxYeHYmh'
MAIL_DEFAULT_SENDER = 'hislota@163.com'

# 头像上传配置
AVATAR_FOLDER = os.path.join('static', 'uploads', 'avatars')
AVATAR_THUMBNAIL_FOLDER = os.path.join('static', 'thumbnails', 'avatars')