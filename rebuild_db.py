from app import app, db
import os
from init_regions import init_regions

def rebuild_database():
    with app.app_context():
        # 删除现有数据库文件
        if os.path.exists('instance/microblog.db'):
            print("删除现有数据库...")
            os.remove('instance/microblog.db')
        
        # 创建所有表
        print("创建新数据库...")
        db.create_all()
        
        # 初始化地区数据
        print("初始化地区数据...")
        init_regions()
        
        print("数据库重建完成！")

if __name__ == '__main__':
    rebuild_database() 