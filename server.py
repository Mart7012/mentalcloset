from typing import Optional

import hmac
import hashlib
import base64
import json

from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "f46729d4720e6a198b9d445d090c76143219b7d6358c1cdec95bf1bfcea013e3"
PASSWORD_SALT = "a4b284fc99d4d219946e3fa9aefd9e7c11377eefdc19f20221eff296ceea2006"

def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg = data.encode(),
        digestmod = hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return  password_hash == stored_password_hash

# чтобы перевести наши пароли в хеш с солью мы использовали следующий код:
# hashlib.sha256(("some_password_1" + PASSWORD_SALT).encode()).hexdigest()

users = {
    "anton@user.com": {
        "name": "Антон",
        "password": "1d72588402446eed719aaec5b4294d7da266227cc5e2718c3e19a99e159b13cc",
        "balance": 1000
    },
    "anna@user.com": {
        "name": "Анна",
        "password": "4049fb4d99de82a98a2ab239697b7f410e78350484903952ce39d178459c091d",
        "balance": 100000
    }
}



@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response


    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланс, {users[valid_username]['balance']}!",
        media_type='text/html')
    

@app.post("/login")
def process_login_page(username : str = Form(...), password : str = Form(...)):
    user = users.get(username)
    """
    Такая конструкция user = users.get(username) в случае отсутствия ключа просто вернет пустое значение
    если бы мы написали user = users[username], то в случае отсутвия все бы упало с ошибкой
    """ 
    if not user or not verify_password(username, password):
        return Response(json.dumps({
            "success": False,
            "message": "Я вас не знаю!!!"
        }), media_type='application/json')

    response = Response(json.dumps({
        "success": True,
        "message": f"Привет, {user['name']}!<br /> Баланс: {user['balance']}"
    }),
                    media_type='application/json')
    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed) 
    return response
