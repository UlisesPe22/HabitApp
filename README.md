# HabitApp
This app is designed to help you track and manage your habits. Below are the instructions to get your app up and running on your local machine.

## Getting Started

Follow these steps to set up and run the app on your computer.

### Prerequisites

- Python 3.x **Note: Download the 64-bits version**
- Visual Studio Code
   
Go to python website (https://www.python.org/downloads/) and pip will be included with it. Once installed, you'll be able to use pip from the command line to install the necessary dependencies for your Flask app. These dependencies are specified in the requirements.txt file

### Installation

1. Download the main folder by clicking on "code" button.
2. Go to downloads and extract all from the zip file "HabitApp-main.zip".
3. Open the "HabitApp-main" on Visual Studio. **Note: make sure to be in the correct folder. If you are not in the correct folder, the next step is not going to work**
5. Open a new terminal on Visual Studio and write "pip install -r requirements.txt" then press enter.If there is an "Error", don't worry, it should be fine (if you find problems check the note at the end of the document)
6. Finally start the database. open a new terminal and type "python". Once you are in the python interpreter type and press enter after each command.
- "from app import app"
- "from app import db"
- "db.create_all()"
- "exit()"
6. Open a new terminal and type "python -m flask run". Click on the link and try the app.

  **Note: if you have issues with the requierments.txt file, you can alternativly use this command:**"pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF Flask-Bcrypt APScheduler email_validator"


  

