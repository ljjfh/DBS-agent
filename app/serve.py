"""Start the local server without trusting client-supplied forwarding headers."""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.server:app", host="127.0.0.1", port=8000, proxy_headers=False)
