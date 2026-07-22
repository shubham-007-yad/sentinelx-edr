from fastapi import FastAPI

app = FastAPI(title="SentinelX EDR")

@app.get("/")
def home():
    return {"message": "SentinelX Backend Running"}

@app.get("/health")
def health():
    return {"status": "healthy"}