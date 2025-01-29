from app import create_app
from app.models import db

app = create_app()

with app.app_context():
    #db.drop_all()
    db.create_all()


'''def reset_database():
    with app.app_context():
        db.drop_all()
        db.create_all'''

if __name__ == "__main__":
   # reset_database()
    app.run(debug=True)

