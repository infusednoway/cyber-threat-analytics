import re
from datetime import datetime


class ValidationError(Exception):
    def __init__(self, field: str, message: str):
        self.field   = field
        self.message = message
        super().__init__(f"{field}: {message}")


class ValidationResult:
    def __init__(self):
        self.errors: list[dict] = []
        self.data:   dict       = {}

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def add_error(self, field: str, message: str):
        self.errors.append({"field": field, "message": message})

    def to_dict(self) -> dict:
        return {"valid": self.is_valid, "errors": self.errors, "data": self.data}


def validate_username(value: str) -> str:
    value = value.strip()
    if len(value) < 3:
        raise ValidationError("username", "Минимальная длина — 3 символа")
    if len(value) > 32:
        raise ValidationError("username", "Максимальная длина — 32 символа")
    if not re.match(r"^[a-zA-Z0-9_\-]+$", value):
        raise ValidationError("username", "Допускаются только латинские буквы, цифры, _ и -")
    return value


def validate_email(value: str) -> str:
    value = value.strip().lower()
    pattern = r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, value):
        raise ValidationError("email", "Некорректный адрес электронной почты")
    return value


def validate_password(value: str, min_length: int = 6) -> str:
    if len(value) < min_length:
        raise ValidationError("password", f"Минимальная длина пароля — {min_length} символов")
    if len(value) > 128:
        raise ValidationError("password", "Максимальная длина пароля — 128 символов")
    return value


def validate_cve_id(value: str) -> str:
    value = value.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", value):
        raise ValidationError("cve_id", "Неверный формат CVE ID (пример: CVE-2024-12345)")
    year = int(value.split("-")[1])
    if year < 1999 or year > datetime.utcnow().year + 1:
        raise ValidationError("cve_id", f"Год CVE вне допустимого диапазона: {year}")
    return value


def validate_date_range(date_from: str, date_to: str) -> tuple[str, str]:
    fmt = "%Y-%m-%d"
    try:
        dt_from = datetime.strptime(date_from, fmt) if date_from else None
        dt_to   = datetime.strptime(date_to,   fmt) if date_to   else None
    except ValueError:
        raise ValidationError("date", "Некорректный формат даты (ожидается YYYY-MM-DD)")
    if dt_from and dt_to and dt_from > dt_to:
        raise ValidationError("date_range", "Дата начала не может быть позже даты окончания")
    return date_from, date_to


def validate_report_form(form: dict) -> ValidationResult:
    result = ValidationResult()

    title = form.get("title", "").strip()
    if not title:
        result.add_error("title", "Название отчёта обязательно")
    elif len(title) > 200:
        result.add_error("title", "Максимальная длина названия — 200 символов")
    else:
        result.data["title"] = title

    date_from = form.get("date_from", "").strip()
    date_to   = form.get("date_to",   "").strip()
    if date_from or date_to:
        try:
            df, dt = validate_date_range(date_from, date_to)
            result.data["date_from"] = df
            result.data["date_to"]   = dt
        except ValidationError as e:
            result.add_error(e.field, e.message)

    notes = form.get("notes", "").strip()
    if len(notes) > 2000:
        result.add_error("notes", "Максимальная длина примечаний — 2000 символов")
    else:
        result.data["notes"] = notes

    return result


def validate_register_form(form: dict) -> ValidationResult:
    result = ValidationResult()

    try:
        result.data["username"] = validate_username(form.get("username", ""))
    except ValidationError as e:
        result.add_error(e.field, e.message)

    try:
        result.data["email"] = validate_email(form.get("email", ""))
    except ValidationError as e:
        result.add_error(e.field, e.message)

    password = form.get("password", "")
    confirm  = form.get("confirm",  "")
    try:
        validate_password(password)
        if password != confirm:
            result.add_error("confirm", "Пароли не совпадают")
        else:
            result.data["password"] = password
    except ValidationError as e:
        result.add_error(e.field, e.message)

    return result


def validate_search_query(value: str, max_length: int = 100) -> str:
    value = value.strip()
    if len(value) > max_length:
        raise ValidationError("search", f"Запрос слишком длинный (максимум {max_length} символов)")
    value = re.sub(r"[<>\"';]", "", value)
    return value


def validate_severity(value: str) -> str:
    allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL", ""}
    value   = value.strip().upper()
    if value not in allowed:
        raise ValidationError("severity", f"Недопустимое значение severity: {value}")
    return value


def validate_positive_int(value, field: str = "value", max_val: int = 10000) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValidationError(field, "Ожидается целое число")
    if v < 0:
        raise ValidationError(field, "Значение должно быть неотрицательным")
    if v > max_val:
        raise ValidationError(field, f"Значение не может превышать {max_val}")
    return v


def sanitize_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("&", "&amp;").replace('"', "&quot;").replace("'", "&#x27;")
    return text.strip()


def validate_pagination(page: str, per_page: str, max_per_page: int = 200) -> tuple[int, int]:
    try:
        p  = max(1, int(page or 1))
        pp = max(1, min(int(per_page or 50), max_per_page))
    except (TypeError, ValueError):
        p, pp = 1, 50
    return p, pp
