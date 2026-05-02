from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from src.auth.auth import login_user, logout_user, register_user, get_current_user

auth_bp = Blueprint("auth_bp", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if get_current_user():
        return redirect(url_for("main_bp.dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        token = login_user(username, password)
        if token:
            session["token"] = token
            return redirect(url_for("main_bp.dashboard"))
        error = "Неверный логин или пароль"
    return render_template("auth/login.html", error=error)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if get_current_user():
        return redirect(url_for("main_bp.dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        if len(username) < 3:
            error = "Имя пользователя должно содержать не менее 3 символов"
        elif len(password) < 6:
            error = "Пароль должен содержать не менее 6 символов"
        elif password != confirm:
            error = "Пароли не совпадают"
        else:
            ok = register_user(username, email, password)
            if ok:
                return redirect(url_for("auth_bp.login"))
            error = "Пользователь с таким именем или email уже существует"
    return render_template("auth/register.html", error=error)


@auth_bp.route("/logout")
def logout():
    token = session.pop("token", None)
    if token:
        logout_user(token)
    return redirect(url_for("auth_bp.login"))
