from fastapi import FastAPI
# Import router module , auth is a custom made name
from routers import auth

app = FastAPI(
    title="Auth API",
    version="1.0.0",
    description="Authentication API with PostgreSQL"
)  # Creates FastAPI application instance

@app.get("/")
def root():
    return "The API is successfully working"
# Include routers
app.include_router(auth.router, prefix="/auth")  
# All auth routes start with /auth and it looks for auth.py within routers DIR
# - main.py imports the auth module from routers package
# - auth.router refers to the APIRouter instance created in routers/auth.py
# - prefix="/auth" means all routes in this router will be under /auth path

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)  # Run ASGI server