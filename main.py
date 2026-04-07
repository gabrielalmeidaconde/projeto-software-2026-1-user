from flask import Flask, request, jsonify
from db import db
from models import User
import os
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    CORS(app)
    
    postgres_user = os.environ.get('POSTGRES_USER', 'appuser')
    postgres_password = os.environ.get('POSTGRES_PASSWORD', 'apppass')
    postgres_url = os.environ.get('POSTGRES_URL', 'localhost')
    
    # Define o padrão, mas permite que o Pytest sobrescreva depois
    db_uri = f"postgresql://{postgres_user}:{postgres_password}@{postgres_url}:5432/users"
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI", db_uri)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    db.init_app(app)


    @app.route("/users", methods=["POST"])
    def create_user():
        data = request.json

        user = User(
            name=data["name"],
            email=data["email"]
        )

        db.session.add(user)
        db.session.commit()

        return jsonify({
            "id": str(user.id),
            "name": user.name,
            "email": user.email
        }), 201

    @app.route("/users/<uuid:user_id>", methods=["GET"])
    def get_user(user_id):
        user = User.query.get_or_404(user_id)

        return jsonify({
            "id": str(user.id),
            "name": user.name,
            "email": user.email
        }), 200

    @app.route("/users/<string:email>/email", methods=["GET"])
    def get_user_by_email(email):
        user = User.query.filter_by(email=email).first_or_404()

        return jsonify({
            "id": str(user.id),
            "name": user.name,
            "email": user.email
        }), 200

    @app.route("/users/<uuid:user_id>", methods=["DELETE"])
    def delete_user(user_id):
        user = User.query.get_or_404(user_id)

        db.session.delete(user)
        db.session.commit()

        return "", 204

    @app.route("/users", methods=["GET"])
    def list_users():
        users = User.query.all()

        return [
            {
                "id": str(user.id),
                "name": user.name,
                "email": user.email
            }
            for user in users
        ], 200

    return app

app = create_app()


if __name__ == "__main__":
    app.run(debug=True, port=5000)
