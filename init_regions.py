import json
from app import app, db, Region

def init_regions():
    # 清空现有数据
    db.session.query(Region).delete()
    db.session.commit()
    
    # 读取地区数据文件
    with open('regions.json', 'r', encoding='utf-8') as f:
        regions_data = json.load(f)
    
    # 添加省级数据
    for province in regions_data:
        province_model = Region(
            name=province['name'],
            level=1
        )
        db.session.add(province_model)
        db.session.flush()  # 获取ID
        
        # 添加市级数据
        for city in province['children']:
            city_model = Region(
                name=city['name'],
                parent_id=province_model.id,
                level=2
            )
            db.session.add(city_model)
            db.session.flush()
            
            # 添加区级数据
            for district in city['children']:
                district_model = Region(
                    name=district['name'],
                    parent_id=city_model.id,
                    level=3
                )
                db.session.add(district_model)
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_regions() 