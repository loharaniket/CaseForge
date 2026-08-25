import sys
f = 'apps/api/src/core/errors.py'
with open(f, 'r') as file:
    content = file.read()
content = content.replace('app.add_exception_handler(AppException, app_exception_handler)', 'app.add_exception_handler(AppException, app_exception_handler)  # type: ignore')
content = content.replace('app.add_exception_handler(RequestValidationError, validation_exception_handler)', 'app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore')
content = content.replace('app.add_exception_handler(StarletteHTTPException, http_exception_handler)', 'app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore')
content = content.replace('app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)', 'app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)  # type: ignore')
content = content.replace('app.add_exception_handler(Exception, unhandled_exception_handler)', 'app.add_exception_handler(Exception, unhandled_exception_handler)  # type: ignore')
with open(f, 'w') as file:
    file.write(content)
