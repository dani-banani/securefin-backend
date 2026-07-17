# SecureFin Backend

### Prerequisites
*   Python 3.10+
*   `pip`

### Installation
1.  **Clone the repository**:
    ```bash
    git clone [<your-repo-url>](https://github.com/dani-banani/securefin-backend)
    ```
2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
3.  **Environment Setup**: Create a `.env` file based on `.env.example` and configure your database and security variables.

### Development
Start the development server:
```bash
uvicorn main:app --reload
