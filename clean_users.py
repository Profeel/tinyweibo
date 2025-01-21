from app import app, db, User

with app.app_context():
    # 获取所有用户
    users = User.query.all()
    print(f"当前共有 {len(users)} 个用户")
    
    # 显示所有用户信息
    for user in users:
        print(f"ID: {user.id}, Email: {user.email}")
    
    # 删除所有用户
    for user in users:
        db.session.delete(user)
    
    # 提交更改
    db.session.commit()
    print("所有用户数据已删除")