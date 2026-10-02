# AS Lab

---

## 1. Project Directory Structure


```text
AS/
├── main.py
├── models.py
├── REQUIREMENTS.txt
├── .env
├── static/
│   └── (css, js, images)
└── templates/
    └── *.html files
```

---

## 2. Virtual Environment Setup


1. **Create the virtual environment:**
   ```bash
   python -m venv venv
   ```

2. **Activate the virtual environment:**
   * **Windows (Command Prompt / PowerShell):**
     ```cmd
     venv\Scripts\activate
     ```
   * **macOS / Linux:**
     ```bash
     source venv/bin/activate
     ```

---

## 3. Install Dependencies
MORE THINGS WILL HAVE TO BE INSTALLED, PUT THEM IN REQUIREMENTS.txt AS THE NEED ARISES

Install the required packages using `pip`:

```bash
pip install fastapi uvicorn sqlalchemy pyjwt requests python-dotenv jinja2 ...
```
```bash
pip install -r REQUIREMENTS.txt
```
---


## 4. Running the Application

Start the  server using **Uvicorn** with the reload flag enabled (so changes update automatically):

```bash
uvicorn main:app --reload
```

## 5. Create and install a server certificate
Install Openssl
```
mkdir certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -sha256 -days 365 -nodes
```
And insert in Common Name "localhost".

### TODO:
```
import uvicorn
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello HTTPS"}

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        ssl_keyfile="certs/server.key",
        ssl_certfile="certs/server.crt",
    )
```