# AS Lab

---
## TODO list
- Complete webapp functionalities (create item posts, purchase items, promote to moderators, etc.)
- Oauth 2.0, even though there's token handling and a local login and register process. Allowing users to click "Sign in with Google" or "Sign in with GitHub" via the Authorization Code Flow.
- Encrypt Database, specifically PII about users, like their delivery address, we can also store creditcard info, but it introduces several difficulties so I'm not sure it's the best idea
- XACML privacy rules
- Install certificate, probably the easiest and best way would be to add a reverse proxy (nginx or other), which acts like a middle man between our app and the outside, ensuring all traffic applies TLS (so we can have HTTPS)
- Content encryption at rest, develop a way to store files like images or others on disk, make it safe so users can't upload a .php and get a reverse shell going.(so, image uploading with protectionss, directory protectios so users cant get /etc/passwords either) and then encrypt the images on the device with the project private key or a different private key (we can use the ones in .env)

## 1. Project Directory Structure


```text
AS/
├── main.py
├── models.py
├── db.py
├── auth.py
├── service.py
├── REQUIREMENTS.txt
├── .env
├── routes/
│   └── admin.py,items.py,mod.py,users.py
├── static/
│   └── (css, js, images)
└── templates/
   └── *.html files

```
main.py: initial webapp logic, links the routes for the rest of the api
routes/file.py: this holds the actuapi API logic for the webapp, so homepage, users, items being added, etc,etc.
models.py: stores the models for the db tables
db.py: holds the functions to begin the db engince with which we can handle the database

(These two files might need to be adapted)
auth.py: handles access control, token generation, passwords, etc. 
service.py: holds the oauth2 scheme
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
