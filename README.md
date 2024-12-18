# Project Title
Tennessee Nutrient Task Force Progress Tracker

# Description
This website displays taskforce data from the TND (Tennessee Nutrient Database), TN Nutrient Reduction Task Force Triennial Report, and the EPA ECHO. It is a stand-alone website with pages for login, dashboard, partners, and four tiers of metrics. It will eventually be part of the TDEC website.

# Navigation
The main folder includes all the html files for the various pages: tiers 1-4, partners, admin, dashboard, login, and main tier page. There are also folders with images that are used by the pages: Tier 1 Images, logos, slideshow, and tier2_imgs. There is a folder (CSS) that contains the stylesheets for each tier page. Lastly, there is a folder (TNDBackend) that contains all the necessary files for backend work.

# Technologies
The core programming languages that are used are HTML and JavaScript. HTML (along with CSS) was used to design all the various pages on the website. JavaScript is used to provide the main functionality of the website. Additional resources that we are using for the website: node.JS, Apache, NPM (Node Package Manger), and PostgreSQL. Node.js is used to run the website and is used to build scalable web applications. Apache is used to process requests from internet users and sends them the requested webpage. NPM is used to install, share, and manage libraries and code from our GitHub repository onto the website. PostgreSQL is used to hold all the data that the website pulls from. Requirements/Installation: This website can be accessed on the Tennessee Tech University WiFi through the following link: https://tnd.tntech.edu. If not on the Tech website or if you want to change/test certain files, you must have the following before installing/running the system: Node.js (v14 or above) installed, PostgreSQL installed and running, SQLite installed for intermediate processing, npm (Node Package Manager), and a terminal/shell for running commands.

# Tests
To test this website, first launch the application server by running “node backend.js” in an open terminal in the TNDBackend folder. After that, open “dashboard.html” and go through every page. Make sure to be logged in as either the admin or a regular user, depending on what you are testing.

# Contact Details
Contributors to this project can be found in the “contributors” tab on the main page of this repository.