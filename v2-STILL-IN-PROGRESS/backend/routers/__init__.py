# routers/__init__.py


print("Routers package initialized!-------------------------------------------------------------------------------")
# This runs when the package is first imported



## Complete Practical Example

# Project Structure:
# text
# my_api/
# ├── main.py
# └── api_endpoints/          # Custom package name
#     ├── __init__.py         # Makes it a proper package
#     ├── authentication.py   # Custom module name
#     ├── customer_management.py
#     └── product_catalog.py
# api_endpoints/init.py:
# python
# """
# API endpoints package - contains all route handlers
# """

# from .authentication import router as auth_router
# from .customer_management import router as customer_router
# from .product_catalog import router as product_router

# # Define public exports
# __all__ = ['auth_router', 'customer_router', 'product_router']

# # Package version
# __version__ = "1.0.0"
# api_endpoints/authentication.py:
# python
# from fastapi import APIRouter

# router = APIRouter(tags=["Authentication"])

# @router.post("/login")
# async def login():
#     return {"message": "Login endpoint"}

# @router.post("/register")
# async def register():
#     return {"message": "Register endpoint"}
# main.py:
# python
# from fastapi import FastAPI
# from api_endpoints import auth_router, customer_router, product_router

# app = FastAPI()

# # Use custom prefixes
# app.include_router(auth_router, prefix="/api/auth")
# app.include_router(customer_router, prefix="/api/customers")
# app.include_router(product_router, prefix="/api/products")

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)


# 5. When You Might Skip __init__.py

# You might omit __init__.py if:
# You're creating a simple, temporary project
# You want to use namespace packages across multiple directories
# You're following a specific framework pattern that doesn't use them
# But for most projects, I recommend using __init__.py because:
# It makes your package intentions explicit
# It provides better tooling support (IDE autocomplete, etc.)
# It allows for package initialization logic
# It's the conventional, expected pattern

# Summary
# Names are completely customizable - use whatever makes sense for your project
# __init__.py is optional but recommended - it makes your code more organized and maintainable
# __init__.py serves multiple purposes - initialization, import control, configuration, and simplification