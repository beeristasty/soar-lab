import asyncio, uvicorn
from app.main import app

# worker hosts the event loop that playbooks run on
uvicorn.run(app, host="0.0.0.0", port=8081)
