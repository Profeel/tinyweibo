from app import app, db, User

with app.app_context():
    # 获取User模型的所有列
    columns = User.__table__.columns
    for column in columns:
        print(f"{column.name}: {column.type}") 